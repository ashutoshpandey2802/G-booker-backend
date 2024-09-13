from django.urls import path
from .views import (
    RegisterAPI, LoginAPI, CreateStoreWithStaffAPI, AddStaffAPI, ManageStaffAPI,
    UpdateManagerProfileAPI, UpdateStoreDetailsAPI, ManageTherapistScheduleAPI,
    UpdateTherapistProfileAPI, RoleDetailsAPI, BookAppointmentAPI, StoreStaffDetailsAPI
)

urlpatterns = [
    # Register and Login APIs
    path('register/', RegisterAPI.as_view(), name='register'),
    path('login/', LoginAPI.as_view(), name='login'),
    
    # Store and Staff Management APIs
    path('stores/create/', CreateStoreWithStaffAPI.as_view(), name='create_store_with_staff'),
    path('stores/<int:store_id>/staff/add/', AddStaffAPI.as_view(), name='add_staff'),
    
    # Manage staff (add, update, delete)
    path('stores/<int:store_id>/staff/manage/', ManageStaffAPI.as_view(), name='manage_staff'),
    path('stores/<int:store_id>/staff/<int:staff_id>/update/', ManageStaffAPI.as_view(), name='update_staff'),
    path('stores/<int:store_id>/staff/<int:staff_id>/delete/', ManageStaffAPI.as_view(), name='delete_staff'),
    path('manager/update-profile/', UpdateManagerProfileAPI.as_view(), name='update-manager-profile'),
    path('store/<int:store_id>/update/', UpdateStoreDetailsAPI.as_view(), name='update-store'),
    

    # Therapist Schedule Management
    path('therapists/<int:therapist_id>/schedule/manage/', ManageTherapistScheduleAPI.as_view(), name='manage_therapist_schedule'),
    path('therapists/schedule/<int:schedule_id>/delete/', ManageTherapistScheduleAPI.as_view(), name='delete_schedule'),
    path('therapist/update-profile/', UpdateTherapistProfileAPI.as_view(), name='update-therapist-profile'),

    # Appointment Booking API and     # Role-specific and General APIs
    path('appointments/book/', BookAppointmentAPI.as_view(), name='book_appointment'),
    path('role-details/', RoleDetailsAPI.as_view(), name='role-details'),
    path('store/<int:store_id>/staff-details/', StoreStaffDetailsAPI.as_view(), name='store-staff-details'),
]
