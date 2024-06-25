# FaceMotionMonitorApp/tests/test_views.py

import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from django.contrib.auth.hashers import make_password
from FaceMotionMonitorApp.models.userProfile_models import UserProfile, Auth  # Correct import

@pytest.mark.django_db
def test_login_view():
    client = APIClient()
    url = reverse('login')

    # Create a user
    user_profile = UserProfile.objects.create(
        name="John",
        surname="Doe",
        email="johndoe@example.com",
        pesel="12345678903"
    )
    Auth.objects.create(
        id=user_profile,  # Correctly reference the user profile
        login="johndoe",
        password=make_password("securepassword"),
        role="PATIENT"
    )

    data = {
        'login': 'johndoe',
        'password': 'securepassword'
    }
    response = client.post(url, data, format='json')
    print(response.data)  # Debug response
    assert response.status_code == 200
    assert 'message' in response.data
