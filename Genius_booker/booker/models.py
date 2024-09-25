from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.exceptions import ValidationError
import random
import time

# Custom user manager
class UserManager(BaseUserManager):
    def create_user(self, phone, password=None, **extra_fields):
        if not phone:
            raise ValueError("Phone number is required")
        user = self.model(phone=phone, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(phone, password, **extra_fields)

# User model
class User(AbstractBaseUser):
    ROLES = (
        ('Owner', 'Owner'),
        ('Manager', 'Manager'),
        ('Therapist', 'Therapist'),
    )
    
    username = models.CharField(max_length=30)
    phone = models.CharField(max_length=15, unique=True)
    email = models.EmailField(null=True, blank=True, unique=True)  # Ensure this works with unique but optional
    role = models.CharField(max_length=10, choices=ROLES, default='Owner')
    
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    
    exp = models.IntegerField(null=True, blank=True)  # In years
    specialty = models.CharField(max_length=255, blank=True, null=True)  
    is_verified = models.BooleanField(default=False)
    description = models.TextField(null=True, blank=True)  # New field for description
    image = models.ImageField(upload_to='user_images/', null=True, blank=True)  # New field for user profile image
    
    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.username if self.username else self.phone

    def clean(self):
        if not self.phone:
            raise ValidationError("Phone number is required")

    def get_store_details(self):
        if self.role != 'Owner':
            return None
        stores = self.owned_stores.prefetch_related('managers', 'therapists').all()
        store_details = []
        for store in stores:
            store_info = {
                'store_name': store.name,
                'managers': store.get_managers_with_therapists(),
                'therapists': store.get_therapists(),
            }
            store_details.append(store_info)
        return store_details

# Store model
class Store(models.Model):
    name = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="owned_stores")
    managers = models.ManyToManyField(User, related_name="managed_stores", limit_choices_to={'role': 'Manager'})
    therapists = models.ManyToManyField(User, related_name="therapist_stores", limit_choices_to={'role': 'Therapist'})
    phone = models.CharField(max_length=15)
    email = models.EmailField(null=True, blank=True)
    opening_days = models.JSONField()  # Ensure proper validation of format
    start_time = models.TimeField()
    end_time = models.TimeField()
    lunch_start_time = models.TimeField(null=True, blank=True)
    lunch_end_time = models.TimeField(null=True, blank=True)
    subscribe = models.BooleanField(default=False)

    class Meta:
        unique_together = ['name', 'address']
        indexes = [
            models.Index(fields=['name', 'address']),  # For better performance
        ]

    def __str__(self):
        return self.name

    def get_therapists(self):
        return [{'therapist_name': therapist.username} for therapist in self.therapists.all()]

    def get_managers_with_therapists(self):
        managers_with_therapists = []
        for manager in self.managers.all():
            manager_info = {
                'manager_name': manager.username,
                'assigned_therapists': [therapist.username for therapist in manager.therapist_stores.filter(id=self.id)]
            }
            managers_with_therapists.append(manager_info)
        return managers_with_therapists

    def get_manager_and_therapist_names(self):
        manager_names = [manager.username for manager in self.managers.all()]
        therapist_names = [therapist.username for therapist in self.therapists.all()]
        return {
            'managers': manager_names,
            'therapists': therapist_names
        }

# Therapist schedule model
class TherapistSchedule(models.Model):
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Confirmed', 'Confirmed'),
        ('Cancelled', 'Cancelled')
    )
    therapist = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'Therapist'})
    store = models.ForeignKey(Store, on_delete=models.CASCADE)
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_day_off = models.BooleanField(default=False)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Pending')  # New status field

    class Meta:
        unique_together = ['therapist', 'store', 'date', 'start_time', 'end_time']
        indexes = [
            models.Index(fields=['therapist', 'store', 'date']),
        ]

    def __str__(self):
        return f'{self.therapist.phone} - {self.date} - {self.start_time} to {self.end_time} - {self.status}'

# Manager schedule model
class ManagerSchedule(models.Model):
    manager = models.ForeignKey(User, on_delete=models.CASCADE, limit_choices_to={'role': 'Manager'})
    store = models.ForeignKey(Store, on_delete=models.CASCADE)
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_day_off = models.BooleanField(default=False)

    class Meta:
        unique_together = ['manager', 'store', 'date', 'start_time', 'end_time']
        indexes = [
            models.Index(fields=['manager', 'store', 'date']),  # For performance
        ]

    def __str__(self):
        return f'{self.manager.phone} - {self.date} - {self.start_time} to {self.end_time}'


class OTP(models.Model):
    phone = models.CharField(max_length=15, unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return (time.time() - self.created_at.timestamp()) > 300  # OTP valid for 5 minutes
