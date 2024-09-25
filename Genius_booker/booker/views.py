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
from .models import ManagerSchedule, User, Store, TherapistSchedule
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import BasePermission,AllowAny
from twilio.rest import Client
from django.conf import settings
import logging
from datetime import timedelta
from .models import OTP  # Adjust the import based on your project structure
from django.utils import timezone
import requests
from random import randint
from twilio.rest import Client
from django.utils.crypto import get_random_string
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.throttling import UserRateThrottle
import base64
from django.utils.http import urlsafe_base64_decode
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from .serializers import (
    RegisterSerializer, StaffSerializer, TherapistSerializer, UserSerializer, StoreSerializer,
    TherapistScheduleSerializer,AddStaffToStoreSerializer,StoreDetailSerializer
)



twilio_client = Client("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN")
# Utility to create user and add them to store roles
@transaction.atomic
def create_user_and_assign_role(staff_member, store=None):
    # Extract the staff details
    role = staff_member.get('role', 'Therapist')
    phone = staff_member.get('phone')
    password = staff_member.get('password')
    email = staff_member.get('email')
    exp = staff_member.get('exp', None)
    specialty = staff_member.get('specialty', None)

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
            role=role,
            exp=exp,
            specialty=specialty
        )
    else:
        # Update existing user with exp and specialty if provided
        if exp is not None:
            user.exp = exp
        if specialty is not None:
            user.specialty = specialty
        user.save()
    
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

def get_store_data(user, stores):
    store_data = []
    for store in stores:
        # Manager schedules
        manager_data = []
        for manager in store.managers.all():
            manager_info = UserSerializer(manager).data
            manager_schedule = ManagerSchedule.objects.filter(manager=manager, store=store).values('date', 'start_time', 'end_time', 'is_day_off')
            manager_info['schedule'] = list(manager_schedule)
            manager_data.append(manager_info)
        
        # Therapist schedules
        therapist_data = []
        for therapist in store.therapists.all():
            therapist_schedule = TherapistSchedule.objects.filter(therapist=therapist, store=store).values('date', 'start_time', 'end_time', 'is_day_off')
            therapist_info = UserSerializer(therapist).data
            therapist_info['schedule'] = list(therapist_schedule)
            therapist_data.append(therapist_info)

        store_data.append({
            "store_id": store.id,
            "store_name": store.name,
            "store_address": store.address,
            "store_phone": store.phone,
            "store_email": store.email,
            "store_schedule": {
                "opening_days": store.opening_days,
                "start_time": store.start_time,
                "end_time": store.end_time,
                "lunch_start_time": store.lunch_start_time,
                "lunch_end_time": store.lunch_end_time
            },
            "managers": manager_data,
            "therapists": therapist_data
        })
    return store_data


class StoreListView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        stores = Store.objects.all().prefetch_related('therapists')
        serializer = StoreDetailSerializer(stores, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

logger = logging.getLogger(__name__)
def verify_recaptcha(recaptcha_response):
    """
    Verifies the Cloudflare Turnstile CAPTCHA response from the user.
    """
    secret_key = getattr(settings, 'TURNSTILE_SECRET_KEY', None)
    if not secret_key:
        return False

    url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
    data = {
        'secret': secret_key,  # Your Cloudflare Turnstile secret key
        'response': recaptcha_response  # The token received from the frontend
    }

    try:
        response = requests.post(url, data=data)
        result = response.json()
        return result.get('success', False)  # Check if CAPTCHA verification was successful
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during CAPTCHA verification: {str(e)}")
        return False


class RegisterAPI(APIView):
    def post(self, request):
        try:
            recaptcha_response = request.data.get('recaptcha')
            if not verify_recaptcha(recaptcha_response):
                return Response({"error": "Invalid CAPTCHA."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = RegisterSerializer(data=request.data)
            password = request.data.get('password')
            password2 = request.data.get('password2')

            if password != password2:
                return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

            if serializer.is_valid():
                user = serializer.save(role='Owner')
                user.is_active = False  # User is not active until verified
                user.save()

                # Generate OTP
                otp_code = str(randint(100000, 999999))
                OTP.objects.create(phone=user.phone, otp=otp_code)

                # Send OTP via SMS using Twilio
                client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
                client.messages.create(
                    body=f"Your OTP for account verification is: {otp_code}",
                    from_=settings.TWILIO_PHONE_NUMBER,
                    to=user.phone
                )

                return Response({"message": "Owner created successfully. An OTP has been sent to your phone."}, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during registration: {str(e)}")
            return Response({"error": "An error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPView(APIView):
    def post(self, request):
        phone = request.data.get('phone')
        otp = request.data.get('otp')

        try:
            otp_record = OTP.objects.get(phone=phone)

            if otp_record.is_expired():
                return Response({"error": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST)

            if otp_record.otp == otp:
                user = User.objects.get(phone=phone)
                user.is_verified = True
                user.is_active = True  # User can now log in
                user.save()

                # Delete the OTP record after verification
                otp_record.delete()

                return Response({"message": "Account verified successfully! You can now log in."}, status=status.HTTP_200_OK)

            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        except OTP.DoesNotExist:
            return Response({"error": "OTP not found"}, status=status.HTTP_404_NOT_FOUND)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)






token_generator = PasswordResetTokenGenerator()

class PasswordResetRequestView(APIView):
    def post(self, request):
        phone = request.data.get('phone')

        try:
            user = User.objects.get(phone=phone)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Generate password reset token and user ID
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)

        # Create the password reset URL
        reset_url = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"

        # Send the reset URL to the user's phone via SMS using Twilio
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        try:
            message = client.messages.create(
                body=f"Hi {user.username},\nUse the link to reset your password: {reset_url}",
                from_=settings.TWILIO_PHONE_NUMBER,
                to=user.phone
            )
        except Exception as e:
            return Response({"error": "Failed to send SMS"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Password reset link sent to your phone."}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        # Decode the user ID from the URL
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid user"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the token is valid
        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate the passwords
        password = request.data.get('new_password')
        password2 = request.data.get('confirm_password')

        if password != password2:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

        # Set the new password and clear reset token
        try:
            validate_password(password)
        except ValidationError as e:
            return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(password)
        user.save()

        return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)


# Login API
class OwnerLoginView(APIView):
        def post(self, request):
            phone = request.data.get('phone')
            password = request.data.get('password')
            user = authenticate(phone=phone, password=password)

            if user and user.role == 'Owner':
                # Fetch the stores owned by the owner
                stores = Store.objects.filter(owner=user).prefetch_related('managers', 'therapists')
                refresh = RefreshToken.for_user(user)

                # Prepare store data including managers and therapists with all details
                store_data =  get_store_data(user, stores)

                # Prepare response data
                data = {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "owner": {
                        "role": user.role,
                        "owner_id": user.id,
                        "name": user.username,
                        "email": user.email,
                        "phone": user.phone
                    },
                    "stores": store_data
                }

                return Response(data, status=status.HTTP_200_OK)

            return Response({"error": "Login with owner credentials"}, status=status.HTTP_403_FORBIDDEN)
    
class ManagerLoginView(APIView):
    def post(self, request):
        phone = request.data.get('phone')
        password = request.data.get('password')
        user = authenticate(phone=phone, password=password)

        if user and user.role == 'Manager':
            # Fetch the stores managed by the manager
            stores = Store.objects.filter(managers=user)
            refresh = RefreshToken.for_user(user)

            # Use helper function to prepare store data
            store_data = get_store_data(user, stores)

            # Fetch manager's own schedule
            manager_schedule = ManagerSchedule.objects.filter(manager=user).values('date', 'start_time', 'end_time', 'is_day_off')

            # Prepare response data
            data = {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "manager": {
                    "role": user.role,
                    "manager_id": user.id,
                    "name": user.username,
                    "email": user.email,
                    "phone": user.phone,
                    "exp": str(user.exp),
                    "schedule": list(manager_schedule)
                },
                "stores": store_data
            }

            return Response(data, status=status.HTTP_200_OK)

        return Response({"error": "Login with manager credentials"}, status=status.HTTP_403_FORBIDDEN)




class TherapistLoginView(APIView):
    def post(self, request):
        phone = request.data.get('phone')
        password = request.data.get('password')
        user = authenticate(phone=phone, password=password)

        if user and user.role == 'Therapist':
            refresh = RefreshToken.for_user(user)

            # Fetch the stores associated with the therapist
            stores = Store.objects.filter(therapists=user)

            # Use helper function to prepare store data
            store_data = get_store_data(user, stores)

            # Fetch therapist's own schedule
            therapist_schedule = TherapistSchedule.objects.filter(therapist=user).values('date', 'start_time', 'end_time', 'is_day_off')

            # Prepare response data
            data = {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "therapist": {
                    "role": user.role,
                    "therapist_id": user.id,
                    "name": user.username,
                    "email": user.email,
                    "phone": user.phone,
                    "exp": str(user.exp),
                    "specialty": user.specialty,
                    "schedule": list(therapist_schedule)
                },
                "stores": store_data
            }

            return Response(data, status=status.HTTP_200_OK)

        return Response({"error": "Login with therapist credentials"}, status=status.HTTP_403_FORBIDDEN)




class IsOwner(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.role == 'Owner'


# Owner - Create Store with multiple staff API


class CreateStoreWithStaffAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsOwner]

    @transaction.atomic  # Ensures atomic transaction
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
            created_staff = []
            for staff_member in staff_data:
                role = staff_member.get('role')
                if role not in ['Manager', 'Therapist']:
                    # Roll back the transaction if an invalid role is provided
                    transaction.set_rollback(True)
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

                    created_staff.append({
                        "staff_id": staff.id,
                        "staff_role": staff.role,
                        "staff_name": staff.username
                    })
                else:
                    # Rollback if any staff creation fails
                    transaction.set_rollback(True)
                    return Response(staff_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            return Response({
                "message": "Store and staff created successfully.",
                "store_id": store.id,
                "store_name": store.name,
                "created_staff": created_staff
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(store_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DeleteStoreAPI(APIView):
    authentication_classes = [JWTAuthentication]  # Ensure you're using JWT for authentication
    permission_classes = [IsAuthenticated, IsOwner]  # Only owners can delete the store

    def delete(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)

        # Check if the user is the owner of the store
        if store.owner != request.user:
            return Response({"detail": "You do not have permission to delete this store."}, status=status.HTTP_403_FORBIDDEN)

        # Perform the deletion
        store.delete()
        return Response({"detail": "Store deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

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
        added_staff = []
        for staff_member in staff_data:
            user = create_user_and_assign_role(staff_member, store)
            added_staff.append({
                "staff_id": user.id,
                "staff_role": user.role,
                "staff_name": user.username
            })
        
        return Response({
            "message": "Staff added successfully.",
            "store_id": store.id,
            "added_staff": added_staff
        }, status=status.HTTP_201_CREATED)


class AddStaffToStoreView(APIView):
    def post(self, request):
        serializer = AddStaffToStoreSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            staff = serializer.create_staff(serializer.validated_data)
            return Response({"message": f"Staff {staff.role} added to store successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Add, Update, and Delete Staff API (Owner and Manager)
class ManageStaffAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        
        # Owner or Manager permission checks
        if not (request.user.role == 'Owner' or request.user in store.managers.all() or request.user.store == store):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        added_staff = []
        staff_data = request.data.get('staff', [])
        for staff_member in staff_data:
            user = create_user_and_assign_role(staff_member, store)
            added_staff.append({
                "staff_id": user.id,
                "staff_role": user.role,
                "staff_name": user.username
            })
        return Response({
            "message": "Staff added successfully.",
            "store_id": store.id,
            "added_staff": added_staff
        }, status=status.HTTP_201_CREATED)

    def put(self, request, store_id, staff_id):
        store = get_object_or_404(Store, id=store_id)
        staff_member = get_object_or_404(User, id=staff_id)
        
        # Owner or Manager permission check
        if request.user.role == 'Owner' and request.user.store == store:
            pass  # Owner can modify all
        elif request.user.role == 'Manager' and request.user in store.managers.all() and staff_member.role == 'Therapist':
            pass  # Manager can modify Therapists only
        elif request.user.role == 'Therapist' and request.user == staff_member:
            pass  # Therapists can only modify their own schedules
        else:
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        # Check if there is schedule data in the request
        schedule_data = request.data.get('schedule', None)
        if schedule_data:
            # Update the therapist's schedule
            self.update_schedule(staff_member, store, schedule_data)

        # Update staff member details (if there are any other updates)
        serializer = StaffSerializer(staff_member, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Staff updated successfully.",
                "staff_id": staff_member.id,
                "store_id": store.id
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, store_id, staff_id):
        store = get_object_or_404(Store, id=store_id)
        staff_member = get_object_or_404(User, id=staff_id)

        # Owner or Manager permission check
        if request.user.role == 'Owner' and request.user.store == store:
            pass  # Owner can delete all
        elif request.user.role == 'Manager' and request.user in store.managers.all() and staff_member.role == 'Therapist':
            pass  # Manager can delete Therapists only
        elif request.user.role == 'Therapist' and request.user == staff_member:
            pass  # Therapists can only delete their own schedules
        else:
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        store.managers.remove(staff_member) if staff_member.role == 'Manager' else store.therapists.remove(staff_member)
        return Response({
            "message": "Staff deleted successfully.",
            "staff_id": staff_member.id,
            "store_id": store.id
        }, status=status.HTTP_200_OK)

    def update_schedule(self, therapist, store, schedule_data):
        """
        Updates the schedule for the given therapist in the specified store.
        """
        # Assuming you have a TherapistSchedule model
        for schedule_item in schedule_data:
            TherapistSchedule.objects.update_or_create(
                therapist=therapist,
                store=store,
                start_time=schedule_item.get('start'),
                defaults={
                    'title': schedule_item.get('title'),
                    'end_time': schedule_item.get('end'),
                    'background_color': schedule_item.get('backgroundColor')
                }
            )



# Manage Therapist Schedules and Appointments API
class ManageTherapistScheduleAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, therapist_id):
        therapist = get_object_or_404(User, id=therapist_id, role='Therapist')

        if not (request.user.role == 'Owner' or request.user.role == 'Manager'):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = TherapistScheduleSerializer(data=request.data)
        if serializer.is_valid():
            schedule = serializer.save(therapist=therapist)
            return Response({
                "message": "Schedule created successfully.",
                "schedule_id": schedule.id,
                "therapist_id": therapist.id
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, schedule_id):
        schedule = get_object_or_404(TherapistSchedule, id=schedule_id)
        therapist = schedule.therapist

        # Check if the user is authorized to update the schedule (Owner, Manager, or the Therapist)
        if not (request.user.role == 'Owner' or request.user.role == 'Manager' or request.user == therapist):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        # Validate and update the schedule
        serializer = TherapistScheduleSerializer(schedule, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Schedule updated successfully.",
                "schedule_id": schedule.id,
                "therapist_id": therapist.id
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, schedule_id):
        schedule = get_object_or_404(TherapistSchedule, id=schedule_id)
        if not (request.user.role == 'Owner' or request.user.role == 'Manager'):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        therapist_id = schedule.therapist.id
        schedule.delete()
        return Response({
            "message": "Schedule deleted successfully",
            "schedule_id": schedule_id,
            "therapist_id": therapist_id
        }, status=status.HTTP_200_OK)


# Appointment Booking API

class BookAppointmentAPI(APIView):
    permission_classes = []  # Remove any restrictions so anyone can book an appointment

    def post(self, request):
        # Extract data from the request
        name = request.data.get('name')
        phone = request.data.get('phone')
        email = request.data.get('email', None)  
        therapist_data = request.data.get('therapist', {})  # Therapist is an object
        therapist_id = therapist_data.get('value')  # Get therapist id from the therapist object
        store_id = request.data.get('store_id')  # Assuming store_id is sent
        date = request.data.get('date')
        start_time = request.data.get('startTime')
        end_time = request.data.get('endTime')

        # Debugging log
        print(f"Received data: name={name}, phone={phone}, email={email}, therapist_id={therapist_id}, store_id={store_id}, date={date}, start_time={start_time}, end_time={end_time}")

        # Ensure mandatory fields are provided
        if not name or not phone or not therapist_id or not date or not start_time or not end_time:
            return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the therapist from the database
            therapist = get_object_or_404(User, id=therapist_id, role='Therapist')
        except User.DoesNotExist:
            return Response({"error": "Therapist not found or incorrect role"}, status=status.HTTP_404_NOT_FOUND)

        # Assuming store_id is provided (you may adjust if it's part of therapist details)
        try:
            store = get_object_or_404(Store, id=store_id)
        except Store.DoesNotExist:
            return Response({"error": "Store not found"}, status=status.HTTP_404_NOT_FOUND)

        # Ensure the selected therapist is associated with the selected store
        if therapist not in store.therapists.all():
            return Response({"error": "Selected therapist is not assigned to this store"}, status=status.HTTP_400_BAD_REQUEST)

        # Parse the date and time
        try:
            date = datetime.strptime(date, "%Y-%m-%d").date()
            start_time = datetime.strptime(start_time, "%H:%M").time()
            end_time = datetime.strptime(end_time, "%H:%M").time()
        except ValueError:
            return Response({"error": "Invalid date or time format"}, status=status.HTTP_400_BAD_REQUEST)

        # Check for conflicts with the therapist's schedule
        existing_bookings = TherapistSchedule.objects.filter(
            therapist=therapist, store=store, date=date,
            start_time__lt=end_time, end_time__gt=start_time
        )

        if existing_bookings.exists():
            return Response({"error": "Therapist is already booked during this time slot"}, status=status.HTTP_400_BAD_REQUEST)

        # Create the appointment data
        schedule_data = {
            "therapist": therapist.id,
            "store": store.id,
            "user_name": name,  # User name from request
            "user_phone": phone,  # Phone from request
            "user_email": email,  # Email from request (optional)
            "date": date,
            "start_time": start_time,
            "end_time": end_time
        }

        # Save the appointment via serializer
        serializer = TherapistScheduleSerializer(data=schedule_data)
        if serializer.is_valid():
            appointment = serializer.save()

            # Send SMS to the user confirming the booking
            message_body = (
                f"Dear {name}, your appointment at {store.name} "
                f"with {therapist.username} is confirmed for {date} "
                f"from {start_time} to {end_time}. Thank you!"
            )
            self.send_sms(phone, message_body)

            # Notify therapist and manager
            self.notify_therapist_and_manager(therapist, store, date, start_time, end_time, name)

            return Response({
                "message": "Appointment booked successfully",
                "appointment_id": appointment.id,
                "therapist_id": therapist.id,
                "store_id": store.id,
                "user_name": name
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_sms(self, to, message_body):
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

    def notify_therapist_and_manager(self, therapist, store, date, start_time, end_time, user_name):
        """
        Notify the therapist and the store manager about the booked appointment.
        """
        phone_number_therapist = therapist.phone
        phone_number_manager = store.manager.phone if hasattr(store, 'manager') else None

        # Message to the therapist
        message_body_therapist = (
            f"Dear {therapist.username}, you have a new appointment at {store.name} "
            f"on {date} from {start_time} to {end_time}. "
            f"Booked by: {user_name}."
        )
        self.send_sms(phone_number_therapist, message_body_therapist)

        # Message to the manager if available
        if phone_number_manager:
            message_body_manager = (
                f"Dear {store.manager.username}, a new appointment has been booked for {therapist.username} "
                f"at {store.name} on {date} from {start_time} to {end_time}. "
                f"Booked by: {user_name}."
            )
            self.send_sms(phone_number_manager, message_body_manager)


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
            updated_user = User.objects.get(id=user.id)  # Fetch updated user data
            
            return Response({
                "message": "Profile updated successfully",
                "user_id": updated_user.id,
                "username": updated_user.username,
                "phone": updated_user.phone,
                "email": updated_user.email,
                "experience": updated_user.exp,  # Ensure that experience is correctly included
                "specialty": updated_user.specialty
            }, status=status.HTTP_200_OK)
        
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
            updated_user = User.objects.get(id=user.id)  # Fetch updated user data
            return Response({
                "message": "Profile updated successfully",
                "user_id": updated_user.id,
                "username": updated_user.username,
                "phone": updated_user.phone,
                "email": updated_user.email,
                "experience": updated_user.exp,
                "specialty": updated_user.specialty
            }, status=status.HTTP_200_OK)
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
            return Response({
                "message": "Store updated successfully",
                "store_id": store.id
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Store and Staff Details API
class StoreStaffDetailsAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        if not (request.user.role == 'Owner' or request.user in store.managers.all()):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        store_serializer = StoreSerializer(store)

        # Staff details with experience and specialty for therapists
        therapist_data = []
        for therapist in store.therapists.all():
            therapist_data.append({
                "therapist_id": therapist.id,
                "therapist_name": therapist.username,
                "therapist_exp": therapist.exp,  # Add experience field
                "therapist_specialty": therapist.specialty  # Add specialty field
            })

        # Manager details with only experience
        manager_data = []
        for manager in store.managers.all():
            manager_data.append({
                "manager_id": manager.id,
                "manager_name": manager.username,
                "manager_exp": manager.exp  # Add experience field
            })

        return Response({
            "store": store_serializer.data,
            "managers": manager_data,
            "therapists": therapist_data,
        }, status=status.HTTP_200_OK)
        
        
class AllSchedulesAPI(APIView):
    permission_classes = [AllowAny]

    def get(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)

        # Store schedule
        store_schedule = {
            "opening_days": store.opening_days,
            "start_time": store.start_time,
            "end_time": store.end_time,
            "lunch_start_time": store.lunch_start_time,
            "lunch_end_time": store.lunch_end_time
        }

        # Manager schedules
        manager_schedules = []
        for manager in store.managers.all():
            manager_schedule = ManagerSchedule.objects.filter(manager=manager).values('date', 'start_time', 'end_time')
            manager_schedules.append({
                "manager_id": manager.id,
                "manager_name": manager.username,
                "schedule": list(manager_schedule)
            })

        # Therapist schedules
        therapist_schedules = []
        for therapist in store.therapists.all():
            therapist_schedule = TherapistSchedule.objects.filter(therapist=therapist).values('date', 'start_time', 'end_time', 'is_day_off')
            therapist_schedules.append({
                "therapist_id": therapist.id,
                "therapist_name": therapist.username,
                "schedule": list(therapist_schedule)
            })

        return Response({
            "store_schedule": store_schedule,
            "manager_schedules": manager_schedules,
            "therapist_schedules": therapist_schedules
        }, status=status.HTTP_200_OK)


class StoreScheduleAPI(APIView):
    permission_classes = [AllowAny]

    def get(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)
        return Response({
            "store_id": store.id,
            "store_schedule": {
                "opening_days": store.opening_days,
                "start_time": store.start_time,
                "end_time": store.end_time,
                "lunch_start_time": store.lunch_start_time,
                "lunch_end_time": store.lunch_end_time
            }
        }, status=status.HTTP_200_OK)


class ManagerScheduleAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, manager_id):
        manager = get_object_or_404(User, id=manager_id, role='Manager')
        schedule = ManagerSchedule.objects.filter(manager=manager).values('date', 'start_time', 'end_time')
        return Response({
            "manager_id": manager_id,
            "schedule": list(schedule)
    
            }, status=status.HTTP_200_OK)

class TherapistScheduleAPI(APIView):
    # permission_classes = [IsAuthenticated]

    def get(self, request, therapist_id):
        therapist = get_object_or_404(User, id=therapist_id, role='Therapist')
        
        # Get start and end date from query params
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        # If no date range is provided, fetch all schedules
        if start_date and end_date:
            schedules = TherapistSchedule.objects.filter(
                therapist=therapist,
                date__range=[start_date, end_date]
            ).values('date', 'start_time', 'end_time', 'is_day_off')
        else:
            schedules = TherapistSchedule.objects.filter(
                therapist=therapist
            ).values('date', 'start_time', 'end_time', 'is_day_off')

        # If no schedules are found, return an empty list
        if not schedules.exists():
            return Response({
                "therapist_id": therapist_id,
                "therapist_name": therapist.username,
                "schedules": []
            }, status=status.HTTP_200_OK)

        # Format the schedules for calendar display
        formatted_schedules = []
        for schedule in schedules:
            if schedule['is_day_off']:
                formatted_schedules.append({
                    "backgroundColor": "#FF0000",  
                    "borderColor": "#FF0000",      
                    "editable": False,          
                    "start": f"{schedule['date']} {schedule['start_time']}",
                    "end": f"{schedule['date']} {schedule['end_time']}",
                    "title": f"{therapist.username} - Day Off",
                })
            else:
                formatted_schedules.append({
                    "backgroundColor": "#21BA45",  # Green for workdays
                    "borderColor": "#21BA45",      # Green for workdays
                    "editable": True,
                    "start": f"{schedule['date']} {schedule['start_time']}",
                    "end": f"{schedule['date']} {schedule['end_time']}",
                    "title": f"Appointment with {therapist.username}",
                })

        return Response({
            "therapist_id": therapist_id,
            "therapist_name": therapist.username,
            "schedules": formatted_schedules
        }, status=status.HTTP_200_OK)
