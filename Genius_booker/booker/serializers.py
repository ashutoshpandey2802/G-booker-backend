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
    managers = UserSerializer(many=True)
    therapists = UserSerializer(many=True)
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
    
    
    