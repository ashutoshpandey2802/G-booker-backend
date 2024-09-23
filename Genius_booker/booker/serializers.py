from rest_framework import serializers
from .models import User, Store, TherapistSchedule

# User Serializer
from .models import User, Store, TherapistSchedule, ManagerSchedule

class UserSerializer(serializers.ModelSerializer):
    experience = serializers.SerializerMethodField()
    schedule = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id','username', 'role', 'experience', 'phone', 'email', 
            'image', 'description', 'is_active', 'schedule'
        ]

    def update(self, instance, validated_data):
        # Update fields if they are provided in the request
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        return instance
    
    def get_experience(self, instance):
        return f'{instance.exp} years' if instance.role in ['Therapist', 'Manager'] and instance.exp else 'N/A'
    
    def get_schedule(self, instance):
        if instance.role == 'Therapist':
            schedules = TherapistSchedule.objects.filter(therapist=instance)
        elif instance.role == 'Manager':
            schedules = ManagerSchedule.objects.filter(manager=instance)
        else:
            return []

        schedule_data = []
        for schedule in schedules:
            schedule_data.append({
                "backgroundColor": "#21BA45",
                "borderColor": "#21BA45",
                "editable": True,
                "start": schedule.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                "end": schedule.end_time.strftime('%Y-%m-%d %H:%M:%S'),
                "title": instance.username
            })
        return schedule_data
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['username'] = instance.username
        # Role-based conditional logic
        if instance.role == 'Therapist':
            data['exp'] = instance.exp
            data['specialty'] = instance.specialty
        elif instance.role == 'Manager':
            data['exp'] = instance.exp
            data.pop('specialty', None)
        else:
            data.pop('exp', None)
            data.pop('specialty', None)
        
        return data
# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password2 = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['username', 'email', 'phone', 'password', 'password2']

    def validate(self, data):
        """
        Check that the two password fields match.
        """
        if data['password'] != data['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        
        # Optionally, add more password validation rules (Django's validate_password is already called)
        return data

    def validate_email(self, value):
        """
        Check if the email is valid and not already in use.
        """
        if value and User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email is already in use.")
        return value

    def validate_phone(self, value):
        """
        Check if the phone number is unique.
        """
        if User.objects.filter(phone=value).exists():
            raise serializers.ValidationError("Phone number is already in use.")
        return value

    def create(self, validated_data):
        # Remove password2 as it's not needed in the User model
        validated_data.pop('password2')
        
        # Create user
        user = User.objects.create_user(
            username=validated_data['username'],
            phone=validated_data['phone'],
            password=validated_data['password'],
            email=validated_data.get('email', None)  # Email is optional
        )
        return user


# Store Serializer
class StoreSerializer(serializers.ModelSerializer):
    managers = UserSerializer(many=True,required=False)
    therapists = UserSerializer(many=True,required=False)
    owner = serializers.ReadOnlyField(source='owner.id')
    class Meta:
        model = Store
        fields = '__all__'

# Staff Serializer (For Managers and Therapists)
class StaffSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        username = validated_data['username']
        phone = validated_data['phone']
        password = validated_data['password']
        email = validated_data.get('email', None)
        role = validated_data.get('role', None)
        exp = validated_data.get('exp', None)  
        specialty = validated_data.get('specialty', None)  
        
        if role == 'Therapist':
            if exp is None:
                exp = 0  # Default exp to 0 if not provided
            if specialty == '':
                specialty = None  
        elif role == 'Manager':
            if exp is None:
                exp = 0
        

        
        user = User.objects.create_user(
            username=username,  
            phone=phone,
            password=password,
            email=email,
            role=role,
            exp=exp,  
            specialty=specialty
        )
        if role == 'Manager' and exp is not None:
            user.exp = exp  # Assuming exp is a field in the User model for Managers
        elif role == 'Therapist':
            user.exp = exp
            user.specialty = specialty  # Assuming both fields are present in User for Therapists

        user.save()
        return user


class TherapistScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = TherapistSchedule
        fields = '__all__'

    def validate(self, data):
        therapist = data.get('therapist')
        store = data.get('store')
        date = data.get('date')
        start_time = data.get('start_time')
        end_time = data.get('end_time')

        # Check if the therapist is associated with the store
        if therapist and store and therapist not in store.therapists.all():
            raise serializers.ValidationError("Selected therapist is not assigned to this store.")

        # Ensure the end_time is after the start_time
        if start_time and end_time and start_time >= end_time:
            raise serializers.ValidationError("End time must be after start time.")

        # Check for any other custom validations you'd like to enforce

        return data


class TherapistSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'phone', 'password','exp', 'specialty','email']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            phone=validated_data['phone'],
            email=validated_data['email'],
            role='Therapist',
            exp=validated_data.get('exp'),  # Optional
            specialty=validated_data.get('specialty') 
        )
        
        user.set_password(validated_data['password'])
        user.save()
        return user
    
    


class AddStaffToStoreSerializer(serializers.Serializer):
    store_id = serializers.IntegerField(required=False)  # Optional field for store ID
    store_name = serializers.CharField(max_length=255, required=False)  # Optional field for store name
    staff_phone = serializers.CharField(max_length=15)
    username = serializers.CharField(max_length=30)
    staff_email = serializers.EmailField(required=False)
    staff_password = serializers.CharField(write_only=True)
    role = serializers.CharField(max_length=10)  # Accept role as a plain CharField
    exp = serializers.IntegerField(required=False, min_value=0)  # Optional field for exp
    specialty = serializers.CharField(max_length=255, required=False, allow_blank=True)  # Optional for therapists

    def validate_role(self, value):
        """Ensure the role is valid, and allow case-insensitive input."""
        allowed_roles = ['Manager', 'Therapist']
        role = value.capitalize()
        if role not in allowed_roles:
            raise serializers.ValidationError(f"{value} is not a valid role.")
        return role

    def validate(self, data):
        store_id = data.get('store_id')
        store_name = data.get('store_name')
        user = self.context['request'].user

        # Check if either store_id or store_name is provided
        if not store_id and not store_name:
            raise serializers.ValidationError("Either 'store_id' or 'store_name' must be provided.")

        # Try to fetch the store by ID or name
        try:
            if store_id:
                store = Store.objects.get(id=store_id)
            elif store_name:
                store = Store.objects.get(name=store_name)
        except Store.DoesNotExist:
            raise serializers.ValidationError("Store not found.")

        # Check if the user is the owner or manager of the store
        if not (store.owner == user or user in store.managers.all()):
            raise serializers.ValidationError("You are not authorized to add staff to this store.")

        data['store'] = store  # Attach the store object to the data
        return data

    def create_staff(self, validated_data):
        # Create the staff member (Manager or Therapist)
        staff = {
            "phone": validated_data['staff_phone'],
            "username": validated_data['username'],
            "email": validated_data.get('staff_email'),
            "password": validated_data['staff_password'],
            "role": validated_data['role'],
            "exp": validated_data.get('exp'),  # Optional exp
            "specialty": validated_data.get('specialty', '').strip() if validated_data['role'] == 'Therapist' else None
        }

        staff = User.objects.create_user(**staff)
        store = validated_data['store']  # The store we validated

        # Assign the staff to the store based on their role
        if staff.role == 'Manager':
            store.managers.add(staff)
        elif staff.role == 'Therapist':
            store.therapists.add(staff)

        store.save()
        return staff


class StoreDetailSerializer(serializers.ModelSerializer):
    therapists = UserSerializer(many=True, read_only=True)
    
    class Meta:
        model = Store
        fields = ['id', 'name', 'address', 'phone', 'email', 'opening_days', 'start_time', 'end_time', 'lunch_start_time', 'lunch_end_time', 'therapists']
    