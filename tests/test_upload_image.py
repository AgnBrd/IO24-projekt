'''
import os
from io import BytesIO
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, Client
from django.urls import reverse
from PIL import Image
from rest_framework import status
from FaceMotionMonitorApp.models import UserProfile, Auth, Patient, Role
from django.contrib.auth.hashers import make_password

class UploadTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.user_profile = UserProfile.objects.create(
            name="John",
            surname="Doe",
            email="johndoe@example.com",
            pesel="12345678903"
        )
        self.patient = Patient.objects.create(
            date_of_birth="1990-01-01",
            date_of_diagnosis="2020-01-01",
            sex="MALE",
            user_id=self.user_profile
        )
        self.auth = Auth.objects.create(
            id=self.user_profile,
            login="johndoe",
            password=make_password("securepassword"),
            role=Role.PATIENT.value
        )

        self.client.login(username='johndoe', password='securepassword')
        self.session = self.client.session
        self.session['user_id'] = self.user_profile.id
        self.session['user_role'] = 'PATIENT'
        self.session.save()

    def create_test_image(self):
        file = BytesIO()
        image = Image.new('RGB', (100, 100))
        image.save(file, 'jpeg')
        file.seek(0)
        return SimpleUploadedFile('test_image.jpg', file.read(), content_type='image/jpeg')

    def test_upload_image(self):
        url = reverse('capture_photo')
        image = self.create_test_image()
        response = self.client.post(url, {'image': image}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('id', response.data)

    def create_test_video(self):
        video_path = os.path.join(os.path.dirname(__file__), 'sample_video.mp4')
        if not os.path.exists(video_path):
            # Create a sample video file for the test
            with open(video_path, 'wb') as video_file:
                video_file.write(os.urandom(1024 * 1024))  # 1MB random content

        with open(video_path, 'rb') as video_file:
            return SimpleUploadedFile('sample_video.mp4', video_file.read(), content_type='video/mp4')

    def test_upload_video(self):
        url = reverse('add_recording')
        video = self.create_test_video()
        response = self.client.post(url, {'video': video}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('id', response.data)
'''