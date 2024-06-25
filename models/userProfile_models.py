# FaceMotionMonitorApp/models/userProfile_models.py

from django.db import models
from enum import Enum

from FaceMotionMonitorApp.models import Role

class Sex(Enum):
    MALE = 'male'
    FEMALE = 'female'

class UserProfile(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    surname = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    pesel = models.CharField(max_length=11, unique=True)
    pass

class Doctor(models.Model):
    id = models.AutoField(primary_key=True)
    pwz_pwzf = models.CharField(max_length=10, unique=True)
    user_id = models.OneToOneField(UserProfile, on_delete=models.CASCADE)

class Patient(models.Model):
    id = models.AutoField(primary_key=True)
    date_of_birth = models.DateField()
    date_of_diagnosis = models.DateField(null=True)
    sex = models.CharField(max_length=10, choices=[(sex.value, sex.name) for sex in Sex])
    user_id = models.OneToOneField(UserProfile, on_delete=models.CASCADE)

class RefPhotos(models.Model):
    id = models.AutoField(primary_key=True)
    date = models.DateTimeField()
    x_center = models.FloatField()
    y_center = models.FloatField()
    patient_id = models.OneToOneField(Patient, on_delete=models.CASCADE, null=True)

class DoctorAndPatient(models.Model):
    id = models.AutoField(primary_key=True)
    patient_id = models.IntegerField(default=1)
    doctor_id = models.IntegerField(default=1)

class Auth(models.Model):
    id = models.OneToOneField(UserProfile, on_delete=models.CASCADE, primary_key=True)
    login = models.CharField(max_length=100, unique=True, null=True)
    password = models.CharField(max_length=100, null=True)
    role = models.CharField(max_length=10, choices=[(role.value, role.name) for role in Role])

class Recordings(models.Model):
    id = models.AutoField(primary_key=True)
    date = models.DateTimeField()
    time = models.IntegerField()
    patient_id = models.ForeignKey(UserProfile, on_delete=models.PROTECT)

class Frames(models.Model):
    id = models.AutoField(primary_key=True)
    frame_number = models.IntegerField()
    timestamp = models.FloatField()
    x_center = models.FloatField()
    y_center = models.FloatField()
    recording_id = models.ForeignKey(Recordings, on_delete=models.CASCADE)

class FrameLandmarks(models.Model):
    id = models.AutoField(primary_key=True)
    landmark_number = models.IntegerField()
    distance = models.FloatField()
    frame_id = models.ForeignKey(Frames, on_delete=models.CASCADE)

class RefPhotoLandmarks(models.Model):
    ref_photo = models.ForeignKey(RefPhotos, on_delete=models.CASCADE)
    landmark_number = models.IntegerField()
    distance = models.FloatField()

    class Meta:
        unique_together = ('ref_photo', 'landmark_number')

class Reports(models.Model):
    id = models.AutoField(primary_key=True)
    date = models.DateTimeField()
    difference_mouth = models.FloatField()
    difference_2 = models.FloatField()
    patient_id = models.ForeignKey(Patient, on_delete=models.CASCADE)
