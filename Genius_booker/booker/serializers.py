from rest_framework import serializers
from .models import User, Store, TherapistSchedule

# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'phone', 'email', 'role']

# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['phone', 'password', 'email']

    def create(self, validated_data):
        user = User.objects.create_user(
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
        user = User.objects.create_user(
            phone=validated_data['phone'],
            password=validated_data['password'],
            email=validated_data.get('email', None),
            role=validated_data.get('role')
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
        fields = ['username', 'phone', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            phone=validated_data['phone'],
            email=validated_data['email'],
            role='Therapist'
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
    
    


class AddStaffToStoreSerializer(serializers.Serializer):
    store_name = serializers.CharField(max_length=255)
    staff_phone = serializers.CharField(max_length=15)
    staff_email = serializers.EmailField(required=False)
    staff_password = serializers.CharField(write_only=True)
    role = serializers.CharField(max_length=10)  # Accept role as a plain CharField
    
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
        staff = User.objects.create_user(
            phone=validated_data['staff_phone'],
            email=validated_data.get('staff_email', ''),
            password=validated_data['staff_password'],
            role=validated_data['role']
        )
        store = validated_data['store']  # The store we validated

        # Assign the staff to the store based on their role
        if staff.role == 'Manager':
            store.managers.add(staff)
        elif staff.role == 'Therapist':
            store.therapists.add(staff)

        store.save()
        return staff
