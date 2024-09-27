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
from rest_framework import generics
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import BasePermission,AllowAny
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from phonenumbers import parse, is_valid_number, format_number, PhoneNumberFormat
from django.conf import settings
import logging
from datetime import timedelta
from .models import OTP 
from django.utils import timezone
import requests
from random import randint
import phonenumbers
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

    if not phone or not password:
        raise ValidationError("Phone number and password are required to create a staff member.")
    
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
    secret_key = settings.TURNSTILE_SECRET_KEY
    if not secret_key:
        logger.error("TURNSTILE_SECRET_KEY is not set in environment variables.")
        return False

    url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
    data = {
        'secret': secret_key,  # Your Cloudflare Turnstile secret key
        'response': recaptcha_response  # The token received from the frontend
    }

    try:
        response = requests.post(url, data=data)
        result = response.json()
        logger.debug(f"CAPTCHA verification result: {result}")  
        if not result.get('success', False):
            logger.error(f"CAPTCHA failed with error codes: {result.get('error-codes')}")
            return False
        return True
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during CAPTCHA verification: {str(e)}")
        return False



def format_phone_number(phone, country_code="US"):
    try:
        # Clean up the phone number (remove spaces, dashes, etc.)
        phone = ''.join([c for c in phone if c.isdigit() or c == '+'])
        
        # If the phone number starts with a '+', parse it as an international number
        if phone.startswith('+'):
            parsed_number = phonenumbers.parse(phone, None)  # No need to provide a region
        else:
            # Parse the number with the provided country code
            parsed_number = phonenumbers.parse(phone, country_code)

        # Check if the phone number is valid
        if phonenumbers.is_valid_number(parsed_number):
            # Return the formatted phone number in E.164 format
            return phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
        else:
            raise ValueError("Invalid phone number format")
    
    except phonenumbers.phonenumberutil.NumberParseException as e:
        raise ValueError(f"Error formatting phone number: {str(e)}")

class RegisterAPI(APIView):
    def post(self, request):
        try:
            recaptcha_response = request.data.get('recaptcha')
            if not verify_recaptcha(recaptcha_response):
                return Response({"error": "Invalid CAPTCHA."}, status=status.HTTP_400_BAD_REQUEST)

            # Extract phone number from request data
            phone = request.data.get('phone')
            if not phone:
                return Response({"error": "Phone number is required"}, status=status.HTTP_400_BAD_REQUEST)

            # Check if a user with this phone number already exists
            if User.objects.filter(phone=phone).exists():
                return Response({"error": "Phone number already in use"}, status=status.HTTP_400_BAD_REQUEST)

            # Generate OTP and send it via SMS
            otp_code = str(randint(100000, 999999))
            OTP.objects.create(phone=phone, otp=otp_code)

            # Send OTP via SMS using Twilio
            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            try:
                formatted_phone = format_phone_number(phone, 'IN')
                client.messages.create(
                    body=f"Your OTP for account verification is: {otp_code}",
                    from_=settings.TWILIO_PHONE_NUMBER,
                    to=formatted_phone
                )
            except TwilioRestException as e:
                logger.error(f"Twilio error: {str(e)}")
                return Response({"error": "Failed to send OTP. Please try again."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"message": "OTP sent successfully. Please verify your phone to complete registration."}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error during OTP send: {str(e)}")
            return Response({"error": "An error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class CompleteRegistrationAPI(APIView):
    def post(self, request):
        try:
            otp = request.data.get('otp')
            phone = request.data.get('phone')

            # Validate OTP
            try:
                otp_record = OTP.objects.get(phone=phone, otp=otp)
                if otp_record.is_expired():
                    return Response({"error": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST)
            except OTP.DoesNotExist:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

            # OTP is valid, proceed with registration
            password = request.data.get('password')
            password2 = request.data.get('password2')

            if password != password2:
                return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

            # Collect other registration data (e.g., username)
            serializer = RegisterSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save(phone=phone, role='Owner', is_verified=True)
                user.is_active = True  # User can now log in
                user.save()

                # Delete OTP after successful registration
                otp_record.delete()

                return Response({"message": "User registered successfully!"}, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error during registration: {str(e)}")
            return Response({"error": "An error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
        reset_url = f"{settings.FRONTEND_URL}/#/reset-password/?{uid}/{token}/"

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
                
                store_data =  get_store_data(user, stores)

                # response data
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
            # stores managed by the manager
            stores = Store.objects.filter(managers=user)
            refresh = RefreshToken.for_user(user)

            
            store_data = get_store_data(user, stores)

            # manager's own schedule
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

            #stores associated with the therapist
            stores = Store.objects.filter(therapists=user)

            # store data
            store_data = get_store_data(user, stores)

            # therapist's own schedule
            therapist_schedule = TherapistSchedule.objects.filter(therapist=user).values('date', 'start_time', 'end_time', 'is_day_off')

            # response data
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

    @transaction.atomic 
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
    authentication_classes = [JWTAuthentication]  
    permission_classes = [IsAuthenticated, IsOwner]  # Only owners can delete the store

    def delete(self, request, store_id):
        store = get_object_or_404(Store, id=store_id)

        # Check if the user is the owner of the store
        if store.owner != request.user:
            return Response({"detail": "You do not have permission to delete this store."}, status=status.HTTP_403_FORBIDDEN)

        # the deletion
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
        # Get the therapist from the URL parameter
        therapist = get_object_or_404(User, id=therapist_id, role='Therapist')

        # Owners, Managers, and the therapist themselves can create the schedule
        if not (request.user.role == 'Owner' or request.user.role == 'Manager' or request.user == therapist):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        # Extract the schedule data directly from the request body
        schedule_data = request.data

        if not schedule_data:
            return Response({"error": "No schedule data provided."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate and save the schedule, passing context to handle request.user
        serializer = TherapistScheduleSerializer(data=schedule_data, context={'request': request})
        if serializer.is_valid():
            # Save the schedule, with therapist passed explicitly from the URL parameter
            serializer.save(therapist=therapist)
            return Response({
                "message": "Schedule created successfully.",
                "schedule": serializer.data
            }, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def put(self, request, schedule_id):
        schedule = get_object_or_404(TherapistSchedule, id=schedule_id)
        therapist = schedule.therapist

        # Owners, Managers, and the therapist themselves can update the schedule
        if not (request.user.role == 'Owner' or request.user.role == 'Manager' or request.user == therapist):
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        # Handle both single schedule and list of schedules for updating
        schedule_data = request.data.get('schedule', [])
        if not schedule_data:
            return Response({"error": "No schedule data provided."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if schedule_data is a list or a single schedule
        if isinstance(schedule_data, dict):
            schedule_data = [schedule_data]  # Convert single dict to list for uniform processing

        for schedule_item in schedule_data:
            serializer = TherapistScheduleSerializer(schedule, data=schedule_item, partial=True)
            if serializer.is_valid():
                serializer.save()
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Schedule(s) updated successfully."}, status=status.HTTP_200_OK)

    def delete(self, request, schedule_id):
        schedule = get_object_or_404(TherapistSchedule, id=schedule_id)
        therapist = schedule.therapist

        # Owners, Managers, and the therapist themselves can delete the schedule
        if not (request.user.role == 'Owner' or request.user.role == 'Manager' or request.user == therapist):
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
    permission_classes = []  # Allow anyone to book an appointment

    def post(self, request):
        # Extract data from the request
        name = request.data.get('name')
        phone = request.data.get('phone')
        email = request.data.get('email', None)
        therapist_id = request.data.get('therapist_id')  
        store_id = request.data.get('store_id')
        date = request.data.get('date')
        start_time = request.data.get('start_time')
        end_time = request.data.get('end_time')

        # Ensure mandatory fields are provided
        if not name or not phone or not therapist_id or not date or not start_time or not end_time:
            return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch therapist and store
        therapist = get_object_or_404(User, id=therapist_id, role='Therapist')
        store = get_object_or_404(Store, id=store_id)

        # Check therapist association with store
        if therapist not in store.therapists.all():
            return Response({"error": "Selected therapist is not assigned to this store"}, status=status.HTTP_400_BAD_REQUEST)

        # Parse date and time
        try:
            date = datetime.strptime(date, "%Y-%m-%d").date()
            start_time = datetime.strptime(start_time, "%H:%M").time()
            end_time = datetime.strptime(end_time, "%H:%M").time()
        except ValueError:
            return Response({"error": "Invalid date or time format"}, status=status.HTTP_400_BAD_REQUEST)

        # Combine date and time for the schedule
        start_datetime = datetime.combine(date, start_time)
        end_datetime = datetime.combine(date, end_time)

        # Check for overlapping confirmed bookings
        existing_confirmed_bookings = TherapistSchedule.objects.filter(
            therapist=therapist, store=store, date=date,
            start_time__lt=end_datetime.time(), end_time__gt=start_datetime.time(),
            status='Confirmed'
        )

        if existing_confirmed_bookings.exists():
            return Response({"error": "Therapist is already booked during this time slot"}, status=status.HTTP_400_BAD_REQUEST)

        # Create the appointment as 'Pending'
        schedule_data = {
            "therapist": therapist.id,
            "store": store.id,
            "customer_name": name,
            "customer_phone": phone,
            "customer_email": email,
            "date": date,
            "start_time": start_time,
            "end_time": end_time,      
            "status": "Pending",
            "is_day_off": False,
            "title": f"Appointment with {therapist.username}",
            "color": "#00FF00"
        }

        serializer = TherapistScheduleSerializer(data=schedule_data, context={'request': request})
        if serializer.is_valid():
            appointment = serializer.save()

            # Send SMS to the user confirming the booking as 'Pending'
            message_body = (
                f"Dear {name}, your appointment at {store.name} with {therapist.username} is pending for {date} "
                f"from {start_time} to {end_time}. It will be confirmed shortly."
            )
            self.send_sms(phone, message_body)

            # Notify the therapist and manager
            self.notify_therapist_and_manager(therapist, store, date, start_time, end_time, name)

            return Response({
                "message": "Appointment booked successfully",
                "appointment_id": appointment.id,
                "therapist_id": therapist.id,
                "store_id": store.id,
                "customer_name": name
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

    def notify_therapist_and_manager(self, therapist, store, date, start_time, end_time, username):
        phone_number_therapist = therapist.phone
        phone_number_manager = store.manager.phone if hasattr(store, 'manager') else None

        # Message to the therapist
        message_body_therapist = (
            f"Dear {therapist.username}, you have a new appointment at {store.name} "
            f"on {date} from {start_time} to {end_time}. "
            f"Booked by: {username}."
        )
        self.send_sms(phone_number_therapist, message_body_therapist)

        # Message to the manager if available
        if phone_number_manager:
            message_body_manager = (
                f"Dear {store.manager.username}, a new appointment has been booked for {therapist.username} "
                f"at {store.name} on {date} from {start_time} to {end_time}. "
                f"Booked by: {username}."
            )
            self.send_sms(phone_number_manager, message_body_manager)


class UpdateAppointmentStatusAPI(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users should access

    def patch(self, request, appointment_id):
        # Expect 'Confirmed' or 'Cancelled' status actions
        status_action = request.data.get('status', None)
        if status_action not in ['Confirmed', 'Cancelled']:
            return Response({"error": "Invalid status action"}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the appointment
        try:
            appointment = TherapistSchedule.objects.get(id=appointment_id)
        except TherapistSchedule.DoesNotExist:
            return Response({"error": "Appointment not found"}, status=status.HTTP_404_NOT_FOUND)

        # Ensure the user is authorized to modify the appointment
        if not self.is_authorized_user(request.user, appointment):
            return Response({"error": "You are not authorized to modify this appointment"}, status=status.HTTP_403_FORBIDDEN)

        # Update the appointment status
        previous_status = appointment.status  # For logging purposes
        appointment.status = status_action
        appointment.save()

        # Log the status change
        print(f"Appointment {appointment_id} status changed from {previous_status} to {status_action} by {request.user.username}")

        # Notify the user via SMS
        message_body = (
            f"Dear {appointment.customer_name}, your appointment at {appointment.store.name} "
            f"with {appointment.therapist.username} has been {status_action.lower()} for {appointment.date} "
            f"from {appointment.start_time} to {appointment.end_time}."
        )
        self.send_sms(appointment.customer_phone, message_body)

        return Response({"message": f"Appointment {status_action.lower()} successfully"}, status=status.HTTP_200_OK)

    def is_authorized_user(self, user, appointment):
        """
        Determines whether the user is authorized to confirm/cancel the appointment.
        - Owners can manage all appointments for stores they own.
        - Managers can manage all appointments for stores they manage.
        - Therapists can manage only their own appointments.
        """
        if user.role == 'Owner' and appointment.store.owner == user:
            return True
        elif user.role == 'Manager' and user in appointment.store.managers.all():
            return True
        elif user.role == 'Therapist' and appointment.therapist == user:
            return True
        return False

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
                "therapist_exp": therapist.exp,  
                "therapist_specialty": therapist.specialty  
            })

        # Manager details with only experience
        manager_data = []
        for manager in store.managers.all():
            manager_data.append({
                "manager_id": manager.id,
                "manager_name": manager.username,
                "manager_exp": manager.exp  
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

        # Get start and end date from query params (optional)
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        # Fetch therapist's schedule (both own schedule and customer bookings)
        if start_date and end_date:
            therapist_schedule = TherapistSchedule.objects.filter(
                therapist=therapist,
                date__range=[start_date, end_date]
            )
        else:
            therapist_schedule = TherapistSchedule.objects.filter(therapist=therapist)

        # Separate own schedule from customer bookings
        own_schedule = []
        customer_bookings = []

        for slot in therapist_schedule:
            # Consider a schedule without customer info as therapist's own schedule
            if (slot.customer_name == "Unknown Customer" and slot.customer_phone == "Unknown Phone"):
                own_schedule.append(slot)
            else:
                customer_bookings.append(slot)

        # If no customer bookings or own schedules are found, return an empty response
        if not customer_bookings and not own_schedule:
            return Response({
                "therapist_id": therapist_id,
                "therapist_name": therapist.username,
                "schedules": [],
                "pendingBookings": [],
                "confirmedBookings": []
            }, status=status.HTTP_200_OK)

        # Split customer bookings into pending and confirmed
        pending_bookings = []
        confirmed_bookings = []

        for booking in customer_bookings:
            appointment_data = {
                "appointment_id": booking.id,
                "name": booking.customer_name,
                "phone": booking.customer_phone,
                "email": booking.customer_email,  
                "start": f"{booking.date} {booking.start_time}",
                "end": f"{booking.date} {booking.end_time}",
                "date": str(booking.date)
            }

            if booking.status == "Pending":
                pending_bookings.append(appointment_data)
            elif booking.status == "Confirmed":
                confirmed_bookings.append(appointment_data)

        # Prepare own schedule data (non-customer bookings)
        own_schedule_data = [
            {
                "start": f"{slot.date} {slot.start_time}",
                "end": f"{slot.date} {slot.end_time}",
                "date": str(slot.date),
                "title": slot.title,  # e.g., "Working hours" or "Blocked time"
                "color": slot.color  # Optional color coding for visualization purposes
            }
            for slot in own_schedule
        ]

        return Response({
            "therapist_id": therapist_id,
            "therapist_name": therapist.username,
            "schedules": own_schedule_data,
            "pendingBookings": pending_bookings,
            "confirmedBookings": confirmed_bookings
        }, status=status.HTTP_200_OK)

        
class ListAllBookingsAPI(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TherapistScheduleSerializer

    def get_queryset(self):
        user = self.request.user
        if user.role == 'Owner':
            # Owner can view all appointments across all stores they own
            return TherapistSchedule.objects.filter(store__owner=user)
        elif user.role == 'Manager':
            # Manager can view all appointments for stores they manage
            return TherapistSchedule.objects.filter(store__managers=user)
        elif user.role == 'Therapist':
            # Therapist can only view their own appointments
            return TherapistSchedule.objects.filter(therapist=user)
        
        # Filter by status
        status_filter = self.request.query_params.get('status', None)
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        return queryset

class StoreListAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role == 'Owner':
            stores = Store.objects.filter(owner=request.user)
        elif request.user.role == 'Manager':
            stores = Store.objects.filter(managers=request.user)
        elif request.user.role == 'Therapist':
            stores = Store.objects.filter(therapists=request.user)
        else:
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        store_data = [{"id": store.id, "name": store.name} for store in stores]
        return Response(store_data, status=status.HTTP_200_OK)
