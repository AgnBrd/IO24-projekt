# FaceMotionMonitorApp/tests/test_doctor_registration.py

import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from FaceMotionMonitorApp.models.userProfile_models import UserProfile, Doctor, Auth
from django.contrib.auth.hashers import make_password

@pytest.mark.django_db
def test_doctor_registration():
    client = APIClient()
    url = reverse('register-doctor')
    
    data = {
        'name': 'Alice',
        'surname': 'Smith',
        'email': 'alicesmith@example.com',
        'pesel': '98765432101',
        'pwz_pwzf': '1234567890',
        'login': 'alicesmith',
        'password': 'securepassword',
        'role': 'DOCTOR'
    }
    response = client.post(url, data, format='json')
    print(response.data)  # Debug response
    assert response.status_code == 201
    assert 'id' in response.data

    user_profile = UserProfile.objects.get(email='alicesmith@example.com')
    doctor = Doctor.objects.get(user_id=user_profile)
    auth = Auth.objects.get(id=user_profile)
    
    assert doctor.pwz_pwzf == '1234567890'
    assert auth.login == 'alicesmith'
