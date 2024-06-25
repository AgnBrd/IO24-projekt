import pytest
from FaceMotionMonitorApp.models.userProfile_models import Patient, UserProfile, Auth

@pytest.mark.django_db
def test_create_patient():
    user_profile = UserProfile.objects.create(
        name="Alice",
        surname="Smith",
        email="alice@example.com",
        pesel="09876543211"
    )
    patient = Patient.objects.create(
        date_of_birth="1980-01-01",
        date_of_diagnosis="2020-01-01",
        sex="FEMALE",
        user_id=user_profile
    )
    assert patient.user_id == user_profile
    assert patient.date_of_birth == "1980-01-01"
    assert patient.sex == "FEMALE"

@pytest.mark.django_db
def test_create_auth():
    user_profile = UserProfile.objects.create(
        name="Bob",
        surname="Johnson",
        email="bob@example.com",
        pesel="12345098765"
    )
    auth = Auth.objects.create(
        login="bob_j",
        password="securepassword",
        role="DOCTOR",
        id=user_profile
    )
    assert auth.login == "bob_j"
    assert auth.role == "DOCTOR"
    assert auth.id == user_profile
