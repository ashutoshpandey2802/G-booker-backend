from rest_framework import serializers
from .models import User, Store, TherapistSchedule

# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'phone', 'email', 'role','experience', 'specialty']
    def to_representation(self, instance):
        # Call the original `to_representation` method to get the initial serialized data
        data = super().to_representation(instance)
        
        # Role-based conditional logic for `experience` and `specialty`
        if instance.role == 'Therapist':
            # Include both `experience` and `specialty` for therapists
            data['experience'] = instance.experience
            data['specialty'] = instance.specialty
        elif instance.role == 'Manager':
            # Include only `experience` for managers
            data['experience'] = instance.experience
            data.pop('specialty', None)  # Remove `specialty` if it's present
        else:
            # For other roles (e.g., Owner), remove both `experience` and `specialty`
            data.pop('experience', None)
            data.pop('specialty', None)
        
        return data
# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['first_name','last_name' ,'email', 'phone', 'password']

    def create(self, validated_data):
        user = User.objects.create_user(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone=validated_data['phone'],
            password=validated_data['password'],
            email=validated_data.get('email', None)
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
        # Extract values from validated data, with default for last_name as None
        first_name = validated_data['first_name']
        last_name = validated_data.get('last_name', None)
        phone = validated_data['phone']
        password = validated_data['password']
        email = validated_data.get('email', None)
        role = validated_data.get('role', None)
        if last_name == '' or last_name is None:
            validated_data.pop('last_name', None)

        # Create the user, with last_name set to None if not provided
        user = User.objects.create_user(
            first_name=first_name,
            last_name=last_name,  # Could be None, which is acceptable
            phone=phone,
            password=password,
            email=email,
            role=role
        )
        return user


# Therapist Schedule Serializer
class TherapistScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = TherapistSchedule
        fields = '__all__'

class TherapistSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone', 'password','experience', 'specialty']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        user = User.objects.create(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone=validated_data['phone'],
            email=validated_data['email'],
            role='Therapist',
            experience=validated_data.get('experience'),  # Optional
            specialty=validated_data.get('specialty') 
        )
        last_name = validated_data.get('last_name')
        if last_name == '' or last_name is None:
            validated_data.pop('last_name', None)
        user.set_password(validated_data['password'])
        user.save()
        return user
    
    


class AddStaffToStoreSerializer(serializers.Serializer):
    store_name = serializers.CharField(max_length=255)
    staff_phone = serializers.CharField(max_length=15)
    first_name = serializers.CharField(max_length=30)
    last_name = serializers.CharField(max_length=30, required=False, allow_blank=True)
    staff_email = serializers.EmailField(required=False)
    staff_password = serializers.CharField(write_only=True)
    role = serializers.CharField(max_length=10)  # Accept role as a plain CharField
    experience = serializers.IntegerField(required=False, min_value=0)  # Optional field for experience
    specialty = serializers.CharField(max_length=255, required=False, allow_blank=True)  # Optional for therapists
    def validate_role(self, value):
        """Ensure the role is valid, and allow case-insensitive input."""
        allowed_roles = ['Manager', 'Therapist']
        role = value.capitalize()
        if role not in allowed_roles:
            raise serializers.ValidationError(f"{value} is not a valid role.")
        return role

    def validate(self, data):
        store_name = data.get('store_name')
        user = self.context['request'].user

        # Check if the store exists
        try:
            store = Store.objects.get(name=store_name)
        except Store.DoesNotExist:
            raise serializers.ValidationError(f"Store '{store_name}' not found.")

        # Check if the user is the owner or manager of the store
        if not (store.owner == user or user in store.managers.all()):
            raise serializers.ValidationError("You are not authorized to add staff to this store.")

        data['store'] = store  # Attach the store object to the data
        return data

    def create_staff(self, validated_data):
        # Create the staff member (Manager or Therapist)
        staff = {
            "phone": validated_data['staff_phone'],
            "first_name": validated_data['first_name'],
            "email": validated_data.get('staff_email'),
            "password": validated_data['staff_password'],
            "role": validated_data['role'],
            "experience": validated_data.get('experience'),  # Optional experience
            "specialty": validated_data.get('specialty', '').strip() if validated_data['role'] == 'Therapist' else None
        
        }

        # Only include last_name if it was provided
        last_name = validated_data.get('last_name', '').strip()
        if last_name:
            staff["last_name"] = last_name

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
    therapists = TherapistSerializer(many=True, read_only=True)
    
    class Meta:
        model = Store
        fields = ['id', 'name', 'address', 'phone', 'email', 'opening_days', 'start_time', 'end_time', 'lunch_start_time', 'lunch_end_time', 'therapists']