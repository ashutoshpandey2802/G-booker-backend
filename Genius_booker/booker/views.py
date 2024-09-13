from datetime import datetime
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.exceptions import ValidationError
from django.db import transaction
from .models import User, Store, TherapistSchedule
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication

from twilio.rest import Client
from django.conf import settings
from .serializers import (
    RegisterSerializer, StaffSerializer, TherapistSerializer, UserSerializer, StoreSerializer,
    TherapistScheduleSerializer
)

# Utility to create user and add them to store roles
@transaction.atomic
def create_user_and_assign_role(staff_member, store=None):
    # Extract the staff details
    role = staff_member.get('role', 'Therapist')
    phone = staff_member.get('phone')
    password = staff_member.get('password')
    email = staff_member.get('email')

    # Ensure phone and password are provided
    if not phone or not password:
        raise ValidationError("Phone number and password are required to create a staff member.")
    
    # Check if user already exists
    user = User.objects.filter(phone=phone).first()

    # If user doesn't exist, create a new one
    if not user:
        user = User.objects.create_user(
            phone=phone,
            password=password,
            email=email,
            role=role
        )
    
    # Now, assign the user to the store
    if store:
        if role == 'Manager':
            if store.managers.filter(id=user.id).exists():
                raise ValidationError("This Manager is already assigned to the store.")
            store.managers.add(user)
        elif role == 'Therapist':
            if store.therapists.filter(id=user.id).exists():
                raise ValidationError("This Therapist is already assigned to the store.")
            store.therapists.add(user)

    return user



# Register API for Owner
class RegisterAPI(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save(role='Owner')
            return Response({"message": "Owner created successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Login API
class LoginAPI(APIView):
    def post(self, request):
        phone = request.data.get('phone')
        password = request.data.get('password')
        user = authenticate(phone=phone, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            data = {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "role": user.role,
                "details": None
            }
            if user.role == 'Owner':
                data['details'] = StoreSerializer(user.owned_stores.all(), many=True).data
            elif user.role == 'Manager':
                data['details'] = StoreSerializer(user.managed_stores.all(), many=True).data
            elif user.role == 'Therapist':
                data['details'] = TherapistScheduleSerializer(user.schedules.all(), many=True).data

            return Response(data, status=status.HTTP_200_OK)
        return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

from rest_framework.permissions import BasePermission

class IsOwner(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role == 'Owner'


# Owner - Create Store with multiple staff API
class CreateStoreWithStaffAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated,IsOwner]

    def post(self, request):
        # Ensure the authenticated user is an Owner
        if request.user.role != 'Owner':
            return Response({"detail": "Only owners can create a store."}, status=status.HTTP_403_FORBIDDEN)
        
        store_data = request.data.get('store')
        staff_data = request.data.get('staff', [])

        store_serializer = StoreSerializer(data=store_data)
        if store_serializer.is_valid():
            store = store_serializer.save(owner=request.user)

            # Add multiple staff
            for staff_member in staff_data:
                role = staff_member.get('role')
                if role not in ['Manager', 'Therapist']:
                    return Response({"error": "Staff role must be either 'Manager' or 'Therapist'."}, status=status.HTTP_400_BAD_REQUEST)

                # Create staff member (either Manager or Therapist)
                staff_serializer = StaffSerializer(data=staff_member)
                if staff_serializer.is_valid():
                    staff = staff_serializer.save()

                    # Assign staff to the store based on role
                    if role == 'Manager':
                        store.managers.add(staff)
                    elif role == 'Therapist':
                        store.therapists.add(staff)
                else:
                    return Response(staff_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            return Response({"message": "Store and staff created successfully."}, status=status.HTTP_201_CREATED)

        return Response(store_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Add Staff to existing store API
class AddStaffAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        
        # Owner or Manager permission checks
        if not (request.user.role == 'Owner' and request.user == store.owner or
                request.user.role == 'Manager' and request.user in store.managers.all()):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        staff_data = request.data.get('staff', [])
        for staff_member in staff_data:
            create_user_and_assign_role(staff_member, store)
        
        return Response({"message": "Staff added successfully."}, status=status.HTTP_201_CREATED)

#to check that not same user added twice:


# Add, Update, and Delete Staff API (Owner and Manager)
class ManageStaffAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        
        # Owner or Manager permission checks
        if not (request.user.role == 'Owner' or request.user in store.managers.all()):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        staff_data = request.data.get('staff', [])
        for staff_member in staff_data:
            create_user_and_assign_role(staff_member, store)
        return Response({"message": "Staff added successfully."}, status=status.HTTP_201_CREATED)

    def put(self, request, store_id, staff_id):
        store = get_object_or_404(Store, id=store_id)
        staff_member = get_object_or_404(User, id=staff_id)
        
        # Owner or Manager permission checks
        if not (request.user.role == 'Owner' or request.user in store.managers.all()):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        serializer = StaffSerializer(staff_member, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Staff updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, store_id, staff_id):
        store = get_object_or_404(Store, id=store_id)
        staff_member = get_object_or_404(User, id=staff_id)

        # Owner or Manager permission checks
        if not (request.user.role == 'Owner' or request.user in store.managers.all()):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        store.managers.remove(staff_member)  # or
        store.therapists.remove(staff_member)
        return Response({"message": "Staff deleted successfully"}, status=status.HTTP_200_OK)


# Manage Therapist Schedules and Appointments API
class ManageTherapistScheduleAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, therapist_id):
        therapist = get_object_or_404(User, id=therapist_id, role='Therapist')

        if not (request.user.role == 'Owner' or request.user.role == 'Manager'):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = TherapistScheduleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(therapist=therapist)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, schedule_id):
        schedule = get_object_or_404(TherapistSchedule, id=schedule_id)
        if not (request.user.role == 'Owner' or request.user.role == 'Manager'):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        schedule.delete()
        return Response({"message": "Schedule deleted successfully"}, status=status.HTTP_200_OK)


# Appointment Booking API
from twilio.rest import Client
from django.conf import settings

class BookAppointmentAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        therapist_id = request.data.get('therapist_id')
        store_id = request.data.get('store_id')
        date = request.data.get('date')
        start_time = request.data.get('start_time')
        end_time = request.data.get('end_time')

        therapist = get_object_or_404(User, id=therapist_id, role='Therapist')
        store = get_object_or_404(Store, id=store_id)

        date = datetime.strptime(date, "%Y-%m-%d").date()
        start_time = datetime.strptime(start_time, "%H:%M").time()
        end_time = datetime.strptime(end_time, "%H:%M").time()

        if therapist not in store.therapists.all():
            return Response({"error": "Therapist is not assigned to this store"}, status=status.HTTP_400_BAD_REQUEST)

        # Check for conflicts in the therapist's schedule
        existing_bookings = TherapistSchedule.objects.filter(
            therapist=therapist, store=store, date=date,
            start_time__lt=end_time, end_time__gt=start_time
        )

        if existing_bookings.exists():
            return Response({"error": "Therapist is already booked during this time slot"}, status=status.HTTP_400_BAD_REQUEST)

        schedule_data = {
            "therapist": therapist_id,
            "store": store_id,
            "date": date,
            "start_time": start_time,
            "end_time": end_time
        }
        
        serializer = TherapistScheduleSerializer(data=schedule_data)
        if serializer.is_valid():
            appointment = serializer.save()

            # Send SMS after a successful booking
            phone_number = request.user.phone  # Assuming the phone number is stored in the user's profile
            message_body = (
                f"Dear {request.user.first_name}, your appointment at {store.name} "
                f"with {therapist.first_name} {therapist.last_name} is confirmed for {date} "
                f"from {start_time} to {end_time}. Thank you!"
            )
            
            self.send_sms(phone_number, message_body)

            return Response({
                "message": "Appointment booked successfully",
                "therapist": f"{therapist.first_name} {therapist.last_name}"
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_sms(self, to, message_body):
        """Helper function to send SMS using Twilio"""
        account_sid = settings.TWILIO_ACCOUNT_SID
        auth_token = settings.TWILIO_AUTH_TOKEN
        twilio_phone_number = settings.TWILIO_PHONE_NUMBER

        client = Client(account_sid, auth_token)

        try:
            message = client.messages.create(
                from_=twilio_phone_number,
                body=message_body,
                to=to
            )
            print(f"SMS sent: {message.sid}")
        except Exception as e:
            print(f"Failed to send SMS: {str(e)}")


# Get Role Details API
class RoleDetailsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


# Update Manager Profile
class UpdateManagerProfileAPI(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        if user.role != 'Manager':
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Profile updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Update Therapist Profile
class UpdateTherapistProfileAPI(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user = request.user
        if user.role != 'Therapist':
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = TherapistSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Profile updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Update Store Details API
class UpdateStoreDetailsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        if not (request.user.role == 'Owner' or request.user in store.managers.all()):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        serializer = StoreSerializer(store, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Store updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Store and Staff Details API
class StoreStaffDetailsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        if not (request.user.role == 'Owner' or request.user in store.managers.all()):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        store_serializer = StoreSerializer(store)
        staff_serializer = StaffSerializer(store.therapists.all(), many=True)
        return Response({
            "store": store_serializer.data,
            "staff": staff_serializer.data
        }, status=status.HTTP_200_OK)
