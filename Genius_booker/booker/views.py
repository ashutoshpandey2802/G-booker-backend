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

from twilio.rest import Client
from django.conf import settings
from .serializers import (
    RegisterSerializer, StaffSerializer, TherapistSerializer, UserSerializer, StoreSerializer,
    TherapistScheduleSerializer,AddStaffToStoreSerializer,StoreDetailSerializer
)

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


class StoreListView(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        stores = Store.objects.all().prefetch_related('therapists')
        serializer = StoreDetailSerializer(stores, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# Register API for Owner
class RegisterAPI(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            
            user = serializer.save(role='Owner')
            return Response({"message": "Owner created successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
            store_data = []
            for store in stores:
                # Fetching all manager details for the store
                manager_data = []
                for manager in store.managers.all():
                    
                    manager_info = UserSerializer(manager).data
                    manager_schedule = ManagerSchedule.objects.filter(manager=manager, store=store).values('date', 'start_time', 'end_time', 'is_day_off')
                    manager_info['schedule'] = list(manager_schedule)
                    manager_data.append(manager_info)
                
                # Fetching all therapist details for the store, including their schedule
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

            # Prepare store data and the therapists' schedule
            store_data = []
            for store in stores:
                therapist_schedule = []
                therapists = store.therapists.all()
                for therapist in therapists:
                    schedule = TherapistSchedule.objects.filter(therapist=therapist, store=store).values('date', 'start_time', 'end_time', 'is_day_off')
                    therapist_schedule.append({
                        "therapist_id": therapist.id,
                        "therapist_name": therapist.username,
                        "therapist_exp": str(therapist.exp),
                        "therapist_specialty": therapist.specialty, 
                        "schedule": list(schedule),
                        "role": 'Therapist'
                    })

                store_data.append({
                    "store_id": store.id,
                    "store_name": store.name,
                    "store_schedule": {
                        "opening_days": store.opening_days,
                        "start_time": store.start_time,
                        "end_time": store.end_time,
                        "lunch_start_time": store.lunch_start_time,
                        "lunch_end_time": store.lunch_end_time
                    },
                    "therapists": therapist_schedule
                })
            manager_schedule = ManagerSchedule.objects.filter(manager=user).values('date', 'start_time', 'end_time', 'is_day_off')

            # Prepare response data
            data = {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "manager": {
                    "role": user.role,
                    "manager_id": user.id,
                    "name": user.username ,
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

            # Prepare store data and therapist's schedule
            store_data = []
            for store in stores:
                # Fetch therapist's schedule in the current store
                therapist_schedule = TherapistSchedule.objects.filter(therapist=user, store=store).values('date', 'start_time', 'end_time', 'is_day_off')

                store_data.append({
                    "store_id": store.id,
                    "store_name": store.name,
                    "store_schedule": {
                        "opening_days": store.opening_days,
                        "start_time": store.start_time,
                        "end_time": store.end_time,
                        "lunch_start_time": store.lunch_start_time,
                        "lunch_end_time": store.lunch_end_time
                    },
                    "therapist_schedule": list(therapist_schedule)  # Add therapist schedule for this store
                })

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
                    "exp": str(user.exp),  # Assuming 'exp' is a field on the User model
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
        else:
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

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
        else:
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
        store.managers.remove(staff_member) if staff_member.role == 'Manager' else store.therapists.remove(staff_member)
        return Response({
            "message": "Staff deleted successfully.",
            "staff_id": staff_member.id,
            "store_id": store.id
        }, status=status.HTTP_200_OK)


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
            phone_number = request.user.phone  
            message_body = (
                f"Dear {request.user.username}, your appointment at {store.name} "
                f"with {therapist.username} is confirmed for {date} "
                f"from {start_time} to {end_time}. Thank you!"
            )
            
            self.send_sms(phone_number, message_body)

            return Response({
                "message": "Appointment booked successfully",
                "appointment_id": appointment.id,
                "therapist_id": therapist.id,
                "store_id": store.id
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
            return Response({
                "message": "Profile updated successfully",
                "user_id": user.id
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
            return Response({
                "message": "Profile updated successfully",
                "user_id": user.id,  # Return the therapist's ID
                "therapist_name": user.username,  # Return therapist's name for confirmation
                "phone": user.phone,
                "email": user.email,
                "experience": user.exp,  # Assuming exp is a field for experience
                "specialty": user.specialty  # Return updated specialty
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
    permission_classes = [IsAuthenticated]

    def get(self, request, therapist_id):
        therapist = get_object_or_404(User, id=therapist_id, role='Therapist')
        
        # Fetch the therapist's schedules
        schedules = TherapistSchedule.objects.filter(therapist=therapist).values('date', 'start_time', 'end_time', 'is_day_off')

        formatted_schedules = []
        for schedule in schedules:
            formatted_schedules.append({
                "backgroundColor": "#21BA45",  # Customize as needed
                "borderColor": "#21BA45",      # Customize as needed
                "editable": True,
                "start": f"{schedule['date']} {schedule['start_time']}",
                "end": f"{schedule['date']} {schedule['end_time']}",
                "title": f"Appointment with {therapist.username}",
            })

        return Response({
            "therapist_id": therapist_id,
            "therapist_name":therapist.username,
            "schedules": formatted_schedules
        }, status=status.HTTP_200_OK)

