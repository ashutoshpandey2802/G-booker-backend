from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.exceptions import ValidationError

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
    
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    phone = models.CharField(max_length=15, unique=True)
    email = models.EmailField(null=True, blank=True,unique=True)
    role = models.CharField(max_length=10, choices=ROLES, default='Owner')
    
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    
    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return f'{self.first_name} {self.last_name}' if self.first_name and self.last_name else self.phone

    # Owner's stores and their associated staff (managers and therapists)
    def get_store_details(self):
        if self.role != 'Owner':
            return None
        stores = self.owned_stores.prefetch_related('managers', 'therapists').all()
        store_details = []
        for store in stores:
            store_info = {
                'store_name': store.name,
                'managers': [],
                'therapists': []
            }
            for manager in store.managers.all():
                store_info['managers'].append({
                    'manager_name': f'{manager.first_name} {manager.last_name}',
                    'assigned_therapists': [f'{t.first_name} {t.last_name}' for t in manager.therapist_stores.filter(id=store.id)]
                })
            for therapist in store.therapists.all():
                store_info['therapists'].append(f'{therapist.first_name} {therapist.last_name}')
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
    opening_days = models.JSONField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    lunch_start_time = models.TimeField(null=True, blank=True)
    lunch_end_time = models.TimeField(null=True, blank=True)
    subscribe = models.BooleanField(default=False)

    class Meta:
        unique_together = ['name', 'address']  # Ensure store uniqueness

    def __str__(self):
        return self.name

    # Get the list of therapists for a store
    def get_therapists(self):
        return [{'therapist_name': f'{therapist.first_name} {therapist.last_name}'} for therapist in self.therapists.all()]

    # Get managers and assigned therapists for each manager in the store
    def get_managers_with_therapists(self):
        managers_with_therapists = []
        for manager in self.managers.all():
            manager_info = {
                'manager_name': f'{manager.first_name} {manager.last_name}',
                'assigned_therapists': [f'{therapist.first_name} {therapist.last_name}' for therapist in manager.therapist_stores.filter(id=self.id)]
            }
            managers_with_therapists.append(manager_info)
        return managers_with_therapists

    def add_therapist(self, therapist):
        if self.staff.filter(id=therapist.id).exists():
            raise ValidationError("This therapist is already assigned to this store.")
        self.staff.add(therapist)

class StoreStaff(models.Model):
    STORE_ROLES = (
        ('Manager', 'Manager'),
        ('Therapist', 'Therapist'),
    )
    store = models.ForeignKey(Store, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    role = models.CharField(choices=STORE_ROLES, max_length=10)
    phone = models.CharField(max_length=15)
    email = models.EmailField(blank=True,null=True)
    schedule = models.JSONField()  # To store the working days/timings
    
    
    
# Therapist schedule model
class TherapistSchedule(models.Model):
    therapist = models.ForeignKey(User, on_delete=models.CASCADE)
    store = models.ForeignKey(Store, on_delete=models.CASCADE)
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_day_off = models.BooleanField(default=False)

    class Meta:
        unique_together = ['therapist', 'store', 'date', 'start_time', 'end_time']

    def __str__(self):
        return f'{self.therapist.phone} - {self.date} - {self.start_time} to {self.end_time}'
