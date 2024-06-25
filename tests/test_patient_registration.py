# FaceMotionMonitorApp/tests/test_patient_registration.py

import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from django.contrib.auth.hashers import make_password
from FaceMotionMonitorApp.models.userProfile_models import UserProfile, Auth  # Ensure correct import

@pytest.mark.django_db
def test_patient_registration():
    client = APIClient()
    url = reverse('register-patient')
    
    # Print the generated URL for debugging
    print(f"Generated URL: {url}")
    
    # Creating a UserProfile with the provided PESEL
    user_profile = UserProfile.objects.create(
        name="John",
        surname="Doe",
        email="johndoe@example.com",
        pesel="12345678903"
    )
    
    # Ensure the Auth entry is created
    Auth.objects.create(
        id=user_profile,  # Correctly reference the user profile
        login="johndoe",
        password=make_password("securepassword"),
        role="PATIENT"
    )

    data = {
        'name': 'John',
        'surname': 'Doe',
        'email': 'johndoe@example.com',
        'pesel': '12345678903',
        'login': 'johndoe',
        'password': 'securepassword',
        'role': 'PATIENT',
        'date_of_birth': '1990-01-01',
        'sex': 'MALE'
    }
    response = client.patch(url, data, format='json')
    print(response.data)  # Add this line to debug the response
    assert response.status_code == 200
    assert 'message' in response.data  # Check for any specific message or data in the response
    assert response.data['message'] == "Patient registered successfully"  # Check the exact message
    assert response.data['login'] == 'johndoe'
