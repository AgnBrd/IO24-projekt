import pytest
from django.test import Client
from django.urls import reverse
from django.contrib.auth.hashers import make_password
from FaceMotionMonitorApp.models.userProfile_models import UserProfile, Doctor, Patient, DoctorAndPatient, Auth

@pytest.mark.django_db
def test_get_patients_by_doctor():
    client = Client()  # Use Django's Test Client for session management

    doctor_user_profile = UserProfile.objects.create(
        name="Doctor",
        surname="Who",
        email="doctorwho@example.com",
        pesel="12345678910"
    )
    doctor = Doctor.objects.create(user_id=doctor_user_profile, pwz_pwzf="1234567890")
    doctor_auth = Auth.objects.create(
        id=doctor_user_profile,
        login="doctorwho",
        password=make_password("securepassword"),
        role="DOCTOR"
    )

    patient_user_profile = UserProfile.objects.create(
        name="John",
        surname="Doe",
        email="johndoe@example.com",
        pesel="12345678903"
    )
    patient = Patient.objects.create(
        date_of_birth="1990-01-01",
        date_of_diagnosis="2020-01-01",
        sex="MALE",
        user_id=patient_user_profile
    )
    Auth.objects.create(
        id=patient_user_profile,
        login="johndoe",
        password=make_password("securepassword"),
        role="PATIENT"
    )

    DoctorAndPatient.objects.create(doctor_id=doctor.id, patient_id=patient.id)

    # Authenticate the doctor
    client.login(username='doctorwho', password='securepassword')

    # Set session data
    session = client.session
    session['user_id'] = doctor_user_profile.id
    session['user_role'] = 'DOCTOR'
    session.save()

    url = reverse('get_patients_by_doctor')
    response = client.get(url)
    print(response.data)  # Debug response
    assert response.status_code == 200
    assert len(response.data) == 1
    assert response.data[0]['name'] == 'John'
    assert response.data[0]['surname'] == 'Doe'
    assert response.data[0]['email'] == 'johndoe@example.com'
    assert response.data[0]['pesel'] == '12345678903'

    