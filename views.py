import base64
from datetime import datetime
from django.core.files.uploadedfile import InMemoryUploadedFile
import cv2
import numpy as np
from django.core.files.storage import default_storage
from django.http import HttpResponse, StreamingHttpResponse, JsonResponse
from django.views import View
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.shortcuts import render
from rest_framework import views, status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.hashers import make_password
from PIL import Image

from . import services
from .ai_model.brudnopis import VideoProcessor
from .backends.auth_backend import AuthBackend
from .models import Role, Sex, UserProfile, Doctor, Patient, Auth, DoctorAndPatient, RefPhotos, RefPhotoLandmarks, Frames, FrameLandmarks, Reports
from .serializers import (UserProfileSerializer, AuthSerializer, DoctorSerializer,
                          PatientSerializer, DoctorAndPatientSerializer, RefPhotosSerializer, RefPhotoLandmarksSerializer,
                          FramesSerializer, FrameLandmarksSerializer, ReportsSerializer, PatientsSerializer, AuthUpdateSerializer, PatientSerializer1, RecordingsSerializer)
from .services import get_patient_details

def validate_email(value):  # to check if email is taken
    if UserProfile.objects.filter(email=value).exists():
        return False
    return True

def validate_login(value):  # to check if login is taken
    if Auth.objects.filter(login=value).exists():
        return False
    return True

def validate_pwz_pwzf(value):  # to check if pwz is taken
    if Doctor.objects.filter(pwz_pwzf=value).exists():
        return False
    return True

class DoctorRegistration(views.APIView):
    def get(self, request):
        form = DoctorRegistrationForm()
        return render(request, 'register.html', {'form': form})

    def post(self, request):
        request.data['role'] = 'DOCTOR'
        role_value = Role[request.data['role']].value
        pwz = request.data['pwz_pwzf']
        email = request.data['email']
        login1 = request.data['login']
        # checking if the user exists

        if role_value == Role.DOCTOR.value and (
                validate_email(email) and validate_login(login1) and validate_pwz_pwzf(pwz)):

            user_profile_serializer = UserProfileSerializer(data=request.data)
            if user_profile_serializer.is_valid():
                user_profile = user_profile_serializer.save()

                auth_data = {
                    'login': request.data['login'],
                    'password': make_password(request.data['password']),
                    'role': role_value,
                    'id': user_profile.id  # Assuming user profile ID is used in Auth
                }

                doctor_data = {
                    'pwz_pwzf': request.data['pwz_pwzf'],
                    'user_id': user_profile.id
                }
                auth_serializer = AuthSerializer(data=auth_data)
                doctor_serializer = DoctorSerializer(data=doctor_data)

                if auth_serializer.is_valid() and doctor_serializer.is_valid():
                    auth_serializer.save()
                    doctor_serializer.save()
                    return Response(auth_serializer.data, status=status.HTTP_201_CREATED)
                else:
                    errors = {**auth_serializer.errors, **doctor_serializer.errors}
                    return Response(errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(user_profile_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'message': 'Entered data already exist.'}, status=status.HTTP_400_BAD_REQUEST)
class AddPatient(views.APIView):
    def post(self, request):
        role_value = Role['PATIENT'].value
        pesel = request.data.get('pesel')

        try:
            # Get user_id from session
            user_id = request.session.get('user_id')

            doctor = Doctor.objects.get(user_id_id=user_id)
            print(doctor)
            doctor_id = doctor.id
        except Doctor.DoesNotExist:
            return Response({'error': 'User is not logged in or session has expired'},
                            status=status.HTTP_401_UNAUTHORIZED)

        if UserProfile.objects.filter(pesel=pesel).exists():  # patient exists
            user_profile = UserProfile.objects.get(pesel=pesel)
            user_id = user_profile.id

            patient = Patient.objects.get(user_id_id=user_id)
            patient_id = patient.id

            doctor_user_id = Doctor.objects.get(id=doctor_id).user_id

            if Auth.objects.get(id=doctor_user_id).role == Role['DOCTOR'].value:
                if DoctorAndPatient.objects.filter(doctor_id=doctor_id, patient_id=patient_id).exists():
                    # zabezpieczenie sprawdza czy dana para doktor - pacjent juz istenieje
                    return Response({'error': 'This doctor-patient pair already exists'},
                                    status=status.HTTP_400_BAD_REQUEST)

                patient_and_doctor_data = {
                    'patient_id': patient_id,
                    'doctor_id': doctor_id
                }

                patient_doctor_serializer = DoctorAndPatientSerializer(data=patient_and_doctor_data)

                if patient_doctor_serializer.is_valid():
                    patient_doctor_serializer.save()
                    return Response('Patient added to your list', status=status.HTTP_201_CREATED)
                else:
                    return Response(patient_doctor_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': 'User is not authorized, only doctor can add patient'},
                                status=status.HTTP_400_BAD_REQUEST)
        else:  # creating new patient
            user_profile_serializer = UserProfileSerializer(data=request.data)
            doctor_user_id = Doctor.objects.get(id=doctor_id).user_id

            if user_profile_serializer.is_valid() and Auth.objects.get(id=doctor_user_id).role == Role['DOCTOR'].value:
                user_profile = user_profile_serializer.save()

                auth_data = {
                    'login': None,
                    'password': None,
                    'role': role_value,
                    'id': user_profile.id  # Assuming user profile ID is used in Auth
                }

                patient_data = {
                    'date_of_birth': request.data['date_of_birth'],
                    'date_of_diagnosis': request.data.get('date_of_diagnosis', None),
                    'sex': Sex[request.data['sex']].value,
                    'user_id': user_profile.id
                }

                auth_serializer = AuthSerializer(data=auth_data)
                patient_serializer = PatientSerializer(data=patient_data)

                if patient_serializer.is_valid() and auth_serializer.is_valid():
                    patient_serializer.save()

                    patient_and_doctor_data = {
                        'patient_id': patient_serializer.data['id'],
                        'doctor_id': doctor_id,
                    }
                    patient_doctor_serializer = DoctorAndPatientSerializer(data=patient_and_doctor_data)
                    if patient_doctor_serializer.is_valid():
                        auth_serializer.save()
                        patient_doctor_serializer.save()

                        return Response('Patient added ', status=status.HTTP_201_CREATED)
                    else:
                        return Response(patient_doctor_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                else:
                    return Response({'error': 'User is not authorized, only doctor can add patient'},
                                    status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(user_profile_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PatientRegistration(views.APIView):
    def patch(self, request):
        print("PatientRegistration view called")
        request.data['role'] = 'PATIENT'
        role_value = Role[request.data['role']].value
        pesel = request.data['pesel']
        name = request.data['name']
        surname = request.data['surname']
        email = request.data['email']
        login_new = request.data['login']
        password = request.data['password']

        print(f"Request data: {request.data}")

        if UserProfile.objects.filter(pesel=pesel).exists() and role_value == Role['PATIENT'].value:
            user_profile = UserProfile.objects.get(pesel=pesel)

            if user_profile.name == name and user_profile.surname == surname and user_profile.email == email:
                user_id = user_profile.id

                try:
                    user = Auth.objects.get(pk=user_id)
                except Auth.DoesNotExist:
                    return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

                new_data = {
                    'login': login_new,
                    'password': password,
                }
                serializer = AuthUpdateSerializer(user, data=new_data)
                if serializer.is_valid():
                    serializer.save()
                    request.session['user_role'] = 'PATIENT'
                    request.session['user_id'] = user_id
                    request.session.modified = True
                    request.session.save()
                    return Response({"message": "Patient registered successfully", "login": login_new}, status=status.HTTP_200_OK)
                return Response({"error": ""}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': 'User profile data does not match.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response('The patient with a given PESEL number is not in the database', status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        print(request)

        login_value = request.data.get('login')
        password = request.data.get('password')
        auth_backend = AuthBackend()
        user = auth_backend.authenticate(request, login=login_value, password=password)

        if user is not None:
            request.session['user_role'] = user.role
            request.session['user_id'] = user.id_id
            request.session.modified = True
            request.session.save()
            return Response({'message': 'User logged in', 'role': user.role, 'user_id': user.id_id},
                            status=status.HTTP_200_OK)
        else:
            return Response('Invalid login credentials', status=400)

class GetUserRoleView(View):
    def get(self, request):
        login = request.GET.get('login')
        try:
            user = Auth.objects.get(login=login)
            return JsonResponse({'role': user.role})
        except Auth.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)

def generate_frames():
    processor = VideoProcessor()  # call VideoProcessor class from AI model
    while True:
        frame = processor.process_frame()
        if frame is None:
            break
        yield (b'--frame\r\n'  # returns the processed frame as a byte string
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

@api_view(['POST'])
def capture_photo(request):
    data = request.data
    image_data = data['image']

    # Check if image_data is a file or a base64 string
    if isinstance(image_data, InMemoryUploadedFile):
        img = Image.open(image_data)
        img = img.convert('RGB')
        np_arr = np.array(img)
    else:
        image_data = base64.b64decode(image_data.split(',')[1])
        np_arr = np.frombuffer(image_data, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    
    if img is None:
        return Response({'error': 'Failed to decode image'}, status=status.HTTP_400_BAD_REQUEST)

    print(f"Image type: {type(img)}, shape: {np_arr.shape}")

    date_now = datetime.now().isoformat() + "Z"
    user_id = request.session.get('user_id')

    try:
        patient = Patient.objects.get(user_id_id=user_id)
    except Patient.DoesNotExist:
        return Response({'error': 'Patient not found'}, status=status.HTTP_404_NOT_FOUND)

    patient_id = patient.id

    processor = VideoProcessor()
    try:
        img, img_bytes, landmark_list, distances, x_center, y_center = processor.capture_photo(np_arr)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    ref_photo_data = {
        'date': date_now,
        'x_center': x_center,
        'y_center': y_center,
        'patient_id': patient_id
    }

    ref_photos_serializer = RefPhotosSerializer(data=ref_photo_data)

    if ref_photos_serializer.is_valid():
        ref_photo_instance = ref_photos_serializer.save()

        for landmark, distance in distances.items():
            ref_photo_landmarks_data = {
                'distance': distance,
                'landmark_number': landmark,
                'ref_photo': ref_photo_instance.id
            }
            ref_photos_landmarks_serializer = RefPhotoLandmarksSerializer(data=ref_photo_landmarks_data)
            if ref_photos_landmarks_serializer.is_valid():
                ref_photos_landmarks_serializer.save()
            else:
                return Response(ref_photos_landmarks_serializer.errors, status=400)

        return Response(ref_photos_serializer.data, status=201)
    else:
        return Response(ref_photos_serializer.errors, status=400)

@api_view(['GET'])  # streams the video frames to the client
def video_stream(request):
    return StreamingHttpResponse(generate_frames(), content_type='multipart/x-mixed-replace; boundary=frame')

@api_view(['GET'])  # just a message that recoding has started
def start_video_processing(request):
    return HttpResponse("Video processing started.")

@api_view(['POST'])
def add_recording(request):
    user_id = request.session.get('user_id')

    try:
        patient = Patient.objects.get(user_id_id=user_id)  # Pobierz instancję pacjenta
    except Patient.DoesNotExist:
        return Response({'error': 'Patient not found'}, status=status.HTTP_404_NOT_FOUND)

    video_file = request.FILES.get('video')
    if not video_file:
        return Response({'error': 'No video file provided'}, status=status.HTTP_400_BAD_REQUEST)

    file_path = default_storage.save('temp/recording.webm', video_file)
    processor = VideoProcessor()
    try:
        all_frames_data, frame_number_with_max_distance, landmark_list = processor.process_video(file_path)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    date_now = datetime.now().isoformat() + "Z"

    recording_data = {
        'date': date_now,
        'time': 10,
        'patient_id': patient.user_id.id,  # Użyj identyfikatora user_id
    }

    recordings_serializer = RecordingsSerializer(data=recording_data)
    if recordings_serializer.is_valid():
        recording = recordings_serializer.save()

        frame_data = all_frames_data.get(frame_number_with_max_distance)
        if frame_data:
            frame_serializer = FramesSerializer(data={
                'recording_id': recording.id,
                'frame_number': frame_number_with_max_distance,
                'timestamp': frame_data['timestamp'],
                'x_center': frame_data.get('x_center', 0),
                'y_center': frame_data.get('y_center', 0),
            })
            if frame_serializer.is_valid():
                frame = frame_serializer.save()
                frame_id = frame.id
                for landmark_index, distance in frame_data['landmarks'].items():
                    landmark_serializer = FrameLandmarksSerializer(data={
                        'frame_id': frame.id,
                        'landmark_number': landmark_index,
                        'distance': distance,
                    })
                    if landmark_serializer.is_valid():
                        landmark_serializer.save()
                    else:
                        return Response(landmark_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(frame_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        else:
            frame_id = None  # Handle case where frame_data is not available

        if frame_id:
            current_frame_landmarks = FrameLandmarks.objects.filter(frame_id=frame_id)
            ref_photo_id = RefPhotos.objects.filter(patient_id_id=patient.id).order_by('-date').first().id

            current_distances = {landmark.landmark_number: landmark.distance for landmark in current_frame_landmarks}

            ref_landmarks = RefPhotoLandmarks.objects.filter(ref_photo=ref_photo_id)
            ref_distances = {landmark.landmark_number: landmark.distance for landmark in ref_landmarks}
            date_now = datetime.now().isoformat() + "Z"
            differences = {}
            for landmark in ref_distances.keys():
                if landmark in current_distances:
                    differences[landmark] = abs(ref_distances[landmark] - current_distances[landmark])

            report_data = {
                'patient_id': patient.id,
                'date': date_now,
                'difference_mouth': differences.get(61, 0),  # Assuming 61 is a landmark for the mouth
                'difference_2': differences.get(291, 0),  # Assuming 291 is another critical landmark
            }
            report_serializer = ReportsSerializer(data=report_data)
            if report_serializer.is_valid():
                report_serializer.save()

        return Response(recordings_serializer.data, status=status.HTTP_201_CREATED)
    else:
        return Response(recordings_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def calculate_difference(landmark_list, patient_id):
    processor = VideoProcessor()

    # Ensure landmark_list is a list of tuples
    if not isinstance(landmark_list, list) or not all(
            isinstance(point, tuple) and len(point) == 3 for point in landmark_list):
        raise ValueError(
            f"Expected a list of landmark points, got {type(landmark_list)} in incorrect format")

    # Calculate current distances
    current_mouth = processor.calculate_distance_mouth(landmark_list)
    current_eyebrow = (processor.calculate_distance(landmark_list)[55] +
                       processor.calculate_distance(landmark_list)[285]) / 2

    # Get reference distances
    ref_landmarks = services.get_ref_distances_for_landmarks(patient_id, [55, 285, 61, 291])

    # Debugging to understand ref_landmarks format
    print(f"ref_landmarks: {ref_landmarks}")

    # Ensure ref_landmarks is a dictionary where keys are landmark indices and values are numbers
    if not isinstance(ref_landmarks, dict) or not all(
            isinstance(k, int) and isinstance(v, (float, int)) for k, v in ref_landmarks.items()):
        raise ValueError(
            f"Expected a dictionary of landmark points, got {type(ref_landmarks)} in incorrect format")

    # Calculate reference distances without additional processing
    ref_mouth = ref_landmarks[61]
    ref_eyebrow = (ref_landmarks[55] + ref_landmarks[285]) / 2

    # Calculate differences
    eyebrow_diff = current_eyebrow - ref_eyebrow
    mouth_diff = current_mouth - ref_mouth

    return mouth_diff, eyebrow_diff

@api_view(['DELETE'])  # not used
def delete_user(request, user_id):
    try:
        # Delete data from Auth table
        Auth.objects.filter(id=user_id).delete()

        # Check if the user is a patient
        patient = Patient.objects.filter(user_id=user_id).first()
        if patient:
            patient_id = patient.id
            patient.delete()
            # Delete the patient assignment
            DoctorAndPatient.objects.filter(patient_id=patient_id).delete()

        # Check if the user is a doctor
        doctor = Doctor.objects.filter(user_id=user_id).first()
        if doctor:
            doctor_id = doctor.id
            doctor.delete()
            # Delete the doctor assignment
            DoctorAndPatient.objects.filter(doctor_id=doctor_id).delete()

        UserProfile.objects.filter(id=user_id).delete()
        return Response({'message': 'User deleted successfully'}, status=200)

    except Exception as e:
        # Handle exception (e.g., database issue)
        return Response({'error': 'Failed to delete user', 'details': str(e)}, status=500)

@api_view(['DELETE'])  # for admin
def delete_patient(request, patient_id):
    try:
        patient = Patient.objects.filter(id=patient_id).first()
        if patient:
            user_id = patient.user_id_id
            Auth.objects.filter(id=user_id).delete()
            patient.delete()
            DoctorAndPatient.objects.filter(patient_id=patient_id).delete()
            UserProfile.objects.filter(id=user_id).delete()

            return Response({'message': 'Patient deleted successfully'}, status=200)
        else:
            return Response({'error': 'Patient not found'}, status=404)

    except Exception as e:
        return Response({'error': 'Failed to delete patient', 'details': str(e)}, status=500)

@api_view(['GET'])
def get_patients_by_doctor(request):
    try:
        # Get user_id from session
        user_id = request.session.get('user_id')
        if not user_id:
            return Response({'error': 'User is not logged in or session has expired'},
                            status=status.HTTP_401_UNAUTHORIZED)

        try:
            doctor = Doctor.objects.get(user_id=user_id)
        except Doctor.DoesNotExist:
            return Response({'error': 'No doctor found for this user'}, status=status.HTTP_404_NOT_FOUND)

        doctor_id = doctor.id
        doctor_patient_relations = DoctorAndPatient.objects.filter(doctor_id=doctor_id)
        patient_ids = doctor_patient_relations.values_list('patient_id', flat=True)

        patients = Patient.objects.filter(id__in=patient_ids).select_related('user_id')

        serializer = PatientSerializer1(patients, many=True)

        return Response(serializer.data)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def get_reports_for_doctor_view(request, patient_id):
    try:
        # Get user_id from session
        user_id = request.session.get('user_id')
        if not user_id:
            return Response({'error': 'User is not logged in or session has expired'},
                            status=status.HTTP_401_UNAUTHORIZED)

        # Retrieve the doctor associated with this user_id
        try:
            doctor = Doctor.objects.get(user_id=user_id)
        except Doctor.DoesNotExist:
            return Response({'error': 'No doctor found for this user'}, status=status.HTTP_404_NOT_FOUND)

        doctor_id = doctor.id
        # Find all patient IDs associated with the given doctor ID
        if DoctorAndPatient.objects.filter(doctor_id=doctor_id, patient_id=patient_id).exists():
            reports = Reports.objects.filter(patient_id=patient_id)

            serializer = ReportsSerializer(reports, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    except Reports.DoesNotExist:
        return Response({'error': 'No reports found for this patient'}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def patient_details_view(request):
    user_doctor_id = request.session.get('user_id')
    details = get_patient_details(request)
    return Response(details, status=200)

@api_view(['GET'])
def get_reports_for_patient_view(request):
    try:
        # Get user_id from session
        user_id = request.session.get('user_id')
        if not user_id:
            return Response({'error': 'User is not logged in or session has expired'},
                            status=status.HTTP_401_UNAUTHORIZED)

        # Retrieve the doctor associated with this user_id
        try:
            patient_id = Patient.objects.get(user_id=user_id).id
        except Patient.DoesNotExist:
            return Response({'error': 'No patient found for this user'}, status=status.HTTP_404_NOT_FOUND)

        reports = Reports.objects.filter(patient_id=patient_id)

        serializer = ReportsSerializer(reports, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    except Reports.DoesNotExist:
        return Response({'error': 'No reports found for this patient'}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    def post(self, request):
        try:
            # Clear the session data
            request.session.flush()
            return Response({'message': 'User logged out successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def get_all_patients(request):
    try:
        patients = Patient.objects.all()
        serializer = PatientsSerializer(patients, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
