# FaceMotionMonitor/urls.py

from django.contrib import admin
from django.urls import path
from django.views.generic import TemplateView  # Ensure TemplateView is imported
from FaceMotionMonitorApp.views import (
    DoctorRegistration, LoginView, AddPatient, PatientRegistration,
    video_stream, start_video_processing, capture_photo,
    delete_user, GetUserRoleView, get_patients_by_doctor,
    get_reports_for_doctor_view, patient_details_view,
    get_reports_for_patient_view, LogoutView, delete_patient,
    get_all_patients, add_recording
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', DoctorRegistration.as_view(), name='register-doctor'),
    path('addPatient/', AddPatient.as_view(), name='add-patient'),
    path('registerPatient/', PatientRegistration.as_view(), name='register-patient'),
    path('login/', LoginView.as_view(), name='login'),
    path('video-stream/', video_stream, name='video_stream'),
    path('start-video-processing/', start_video_processing, name='start_video_processing'),
    path('capture-photo/', capture_photo, name='capture_photo'),
    path('delete-user/<int:user_id>/', delete_user, name='delete_user'),
    path('patients/by-doctor/', get_patients_by_doctor, name='get_patients_by_doctor'),
    path('reports/doctor/<int:patient_id>/', get_reports_for_doctor_view, name='get_reports_for_doctor'),
    path('patient/details/', patient_details_view, name='patient_details'),
    path('reports/patient/', get_reports_for_patient_view, name='get_reports_for_patient'),
    path('delete_patient/<int:patient_id>/', delete_patient, name='delete_patient'),
    path('patients/', get_all_patients, name='get_all_patients'),
    path('add_recording/', add_recording, name='add_recording'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('get-user-role/', GetUserRoleView.as_view(), name='get_user_role'),
    path('', TemplateView.as_view(template_name='index.html')),
]
