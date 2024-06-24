import base64
import os
from datetime import date, datetime

import cv2
import numpy as np
from django.core.files.storage import default_storage
from django.http import HttpResponseRedirect, HttpResponse, StreamingHttpResponse, JsonResponse, FileResponse
from django.views import View
from rest_framework import views
from rest_framework.decorators import api_view

from . import services
from .ai_model.brudnopis import VideoProcessor
from .ai_model.reports.report import create_report
from .backends.auth_backend import AuthBackend
from .models import Role, Sex, UserProfile
from .serializers import *
from django.contrib.auth import authenticate, login
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .services import get_patient_details


class DoctorRegistration(views.APIView):
    def post(self, request):
        request.data['role'] = 'DOCTOR'
        role_value = Role[request.data['role']].value
        pwz = request.data['pwz_pwzf']
        email = request.data['email']
        login1 = request.data['login']
        # checking if the user exists

        if role_value == Role.DOCTOR.value and not (
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

                if user_profile_serializer.is_valid() and doctor_serializer.is_valid() and auth_serializer.is_valid():

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

    #TODO add data validation (if pesel is in DB, check if the user is the patient)
    def post(self, request):
        role_vale = Role['PATIENT'].value
        pesel = request.data.get('pesel')

        try:
            # Get user_id from session
            user_id = request.session.get('user_id')

            doctor = Doctor.objects.get(user_id_id=user_id)  #tutaj jest problem
            print(doctor)
            doctor_id = doctor.id
        except Doctor.DoesNotExist:
            return Response({'error': 'User is not logged in or session has expired'},
                            status=status.HTTP_401_UNAUTHORIZED)

        if UserProfile.objects.filter(pesel=pesel).exists():  #patient exists
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
                    # to change - get if from info about session?
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
        else:  #creating new patient
            user_profile_serializer = UserProfileSerializer(data=request.data)
            # try:
            #     doctor_id = int(request.data['doctor_id'])
            # except ValueError:
            #     return Response({"error": "Invalid doctor_id"}, status=status.HTTP_400_BAD_REQUEST)
            doctor_user_id = Doctor.objects.get(id=doctor_id).user_id

            if user_profile_serializer.is_valid() and Auth.objects.get(id=doctor_user_id).role == Role['DOCTOR'].value:
                user_profile = user_profile_serializer.save()

                auth_data = {
                    'login': None,
                    'password': None,
                    'role': role_vale,
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

                if patient_serializer.is_valid() and Auth.objects.get(id=doctor_user_id).role == Role['DOCTOR'].value:

                    patient_serializer.save()

                    patient_and_doctor_data = {
                        'patient_id': patient_serializer.data['id'],
                        'doctor_id': doctor_id,
                    }
                    patient_doctor_serializer = DoctorAndPatientSerializer(data=patient_and_doctor_data)
                    if auth_serializer.is_valid() and patient_doctor_serializer.is_valid():
                        auth_serializer.save()
                        patient_doctor_serializer.save()

                        return Response('Patient added ', status=status.HTTP_201_CREATED)
                    else:
                        return Response(auth_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                else:
                    return Response({'error': 'User is not authorized, only doctor can add patient'},
                                    status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(user_profile_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PatientRegistration(views.APIView):
    def patch(self, request):
        request.data['role'] = 'PATIENT'
        role_value = Role[request.data['role']].value
        pesel = request.data['pesel']
        name = request.data['name']
        surname = request.data['surname']
        email = request.data['email']

        login_new = request.data['login']  # to change in auth table
        password = request.data['password']

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
                    return Response(serializer.data, status=status.HTTP_200_OK)
                return Response({"error": ""}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': 'User profile data does not match.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response('The patient with a given PESEL number is not in the database',
                            status=status.HTTP_400_BAD_REQUEST)


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

            return Response('Nieprawidłowe dane logowania', status=400)


class GetUserRoleView(View):
    def get(self, request):
        username = request.GET.get('login')
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


# class CapturePhotoView(APIView):
#     def get(self, request):
#         processor = VideoProcessor()
#         _, img_bytes, landmark_list, distances, x_center, y_center = processor.capture_photo()
#         if img_bytes is None:
#             return HttpResponse("Failed to capture photo.", status=500)
#         return HttpResponse(img_bytes, content_type='image/jpeg')
#

@api_view(['POST'])
def capture_photo(request):
    data = request.data
    image_data = data['image']
    image_data = base64.b64decode(image_data.split(',')[1])
    np_arr = np.frombuffer(image_data, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

    date_now = datetime.now().isoformat() + "Z"

    user_id = request.session.get('user_id')

    patient = Patient.objects.get(user_id_id=user_id)  # tutaj jest problem

    patient_id = patient.id

    processor = VideoProcessor()
    img, img_bytes, landmark_list, distances, x_center, y_center = processor.capture_photo(img)

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
                # Obsłuż błędy walidacji
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
    global frame_id
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
    all_frames_data, frame_number_with_max_distance, landmark_list = processor.process_video(file_path)
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

        # # Save differences into Reports
        # report_data = {
        #     'date': date_now,
        #     'difference_mouth': 1,  #zmienic na mouth_diff jak bedzie dzialac liczenie
        #     'difference_2': 2,  #zmienic na eyebrow_diff jak bedzie dzialac liczenie
        #     'patient_id_id': patient.id,  # Użyj identyfikatora pacjenta
        # }
        # Reports.objects.create(**report_data)

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


# def calculate_difference(landmark_list, patient_id):
#     # distances = [data['distance'] for data in landmarks_data]
#     processor = VideoProcessor()
#
#     #odleglosci z obecnego pomiaru
#     # na razie mamy mouth - odległość między kącikami ust, bez porównaniado zdjęcia bazowego - można ewentualnie zmienić na koniec
#     # mouth = processor.calculate_distance_mouth(landmark_list)
#     # current_eyebrow = (processor.calculate_distance(landmark_list)[55] + processor.calculate_distance(landmark_list)[285]) / 2  #srednia odleglosci brwi od srodka
#     if not isinstance(landmark_list, list) or not all(
#             isinstance(point, tuple) and len(point) == 3 for point in landmark_list):
#         raise ValueError(f"Expected a list of landmark points, got {type(landmark_list)} with incorrect format")
#
#     ref_eyebrow = (processor.calculate_distance(landmark_list[55]) + processor.calculate_distance(
#         landmark_list[285])) / 2
#     # ... rest of the code
#     #odleglosci z base photo
#     ref_landmarks = services.get_ref_distances_for_landmarks(patient_id, [55, 285])
#     # ref_mouth = processor.calculate_distance_mouth(ref_landmarks)
#     ref_eyebrow = processor.calculate_distance(ref_landmarks[55] + processor.calculate_distance(ref_landmarks[285])) / 2 #srednia odleglosc brwi od srodka dla reference photo
#
#
#     # roznica pomiedzy obecnym wynikiem a ze zdjecia bazowego
#     eyebrow_diff = current_eyebrow - ref_eyebrow
#     return mouth, eyebrow_diff
#

def calculate_difference(landmark_list, patient_id):
    processor = VideoProcessor()

    # Upewnij się, że landmark_list jest listą krotek
    if not isinstance(landmark_list, list) or not all(
            isinstance(point, tuple) and len(point) == 3 for point in landmark_list):
        raise ValueError(
            f"Oczekiwana lista krotek punktów orientacyjnych, otrzymano {type(landmark_list)} w niepoprawnym formacie")

    # Obliczanie bieżących odległości
    current_mouth = processor.calculate_distance_mouth(landmark_list)
    current_eyebrow = (processor.calculate_distance(landmark_list)[55] +
                       processor.calculate_distance(landmark_list)[285]) / 2

    # Pobierz odległości referencyjne
    ref_landmarks = services.get_ref_distances_for_landmarks(patient_id, [55, 285, 61, 291])

    # Debugowanie, aby zrozumieć format ref_landmarks
    print(f"ref_landmarks: {ref_landmarks}")

    # Upewnij się, że ref_landmarks jest słownikiem, gdzie klucze to indeksy punktów orientacyjnych, a wartościami są liczby
    if not isinstance(ref_landmarks, dict) or not all(
            isinstance(k, int) and isinstance(v, (float, int)) for k, v in ref_landmarks.items()):
        raise ValueError(
            f"Oczekiwany słownik punktów orientacyjnych, otrzymano {type(ref_landmarks)} w niepoprawnym formacie")

    # Obliczanie odległości referencyjnych bez dodatkowego przetwarzania
    ref_mouth = ref_landmarks[61]
    ref_eyebrow = (ref_landmarks[55] + ref_landmarks[285]) / 2

    # Obliczanie różnic
    eyebrow_diff = current_eyebrow - ref_eyebrow
    mouth_diff = current_mouth - ref_mouth

    return mouth_diff, eyebrow_diff


@api_view(['DELETE'])  # not used
def delete_user(request, user_id):
    try:
        # Usunięcie danych z tabeli Auth
        Auth.objects.filter(id=user_id).delete()

        # Sprawdzenie czy użytkownik jest pacjentem
        patient = Patient.objects.filter(user_id=user_id).first()
        if patient:
            patient_id = patient.id
            patient.delete()
            # Usunięcie przypisania do pacjenta
            DoctorAndPatient.objects.filter(patient_id=patient_id).delete()

        # Sprawdzenie czy użytkownik jest lekarzem
        doctor = Doctor.objects.filter(user_id=user_id).first()
        if doctor:
            doctor_id = doctor.id
            doctor.delete()
            # Usunięcie przypisania do lekarza
            DoctorAndPatient.objects.filter(doctor_id=doctor_id).delete()

        UserProfile.objects.filter(id=user_id).delete()
        return Response({'message': 'User deleted successfully'}, status=200)

    except Exception as e:
        # Obsługa wyjątku (np. gdy wystąpi problem z bazą danych)
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

            # Check if the user is also a doctor and delete if exists
            # doctor = Doctor.objects.filter(user_id=user_id).first()
            # if doctor:
            #     doctor_id = doctor.id
            #     doctor.delete()
            #     # Delete the assignment from the DoctorAndPatient table
            #     DoctorAndPatient.objects.filter(doctor_id=doctor_id).delete()

            return Response({'message': 'Patient deleted successfully'}, status=200)

        else:
            return Response({'error': 'Patient not found'}, status=404)

    except Exception as e:
        # Handle exception (e.g., database issue)
        return Response({'error': 'Failed to delete patient', 'details': str(e)}, status=500)


# def get_ref_photo_landmarks(patient_id):
#     ref_photo = RefPhotos.objects.get(user_id=patient_id)
#     ref_photo_id = ref_photo.id
#     ref_photo_landmarks = RefPhotoLandmarks.objects.filter(ref_photo_id=ref_photo_id)
#     landmarks_list = []
#     for landmark in ref_photo_landmarks:
#         landmarks_list.append([landmark.landmark_number, landmark.distance])
#     return landmarks_list

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

class CreateReportView(APIView):
    def post(self, request):
        try:
            # Generate the report
            user_id = request.session.get('user_id')
            patient_id = Patient.objects.get(user_id=user_id).id

            today = date.today()
            patient_data = get_patient_details(patient_id)
            file_name = patient_data["name"] + "report" + str(today) + ".pdf"
            x = create_report(patient_id)

            # Path to the generated PDF
            file_path = os.path.join(os.getcwd(), x)
            return Response({'error': 'dziala'}, status=status.HTTP_200_OK)
            # Return the PDF file as a response
            # if os.path.exists(file_path):
            #     with open(file_path, 'rb') as pdf_file:
            #         response = FileResponse(pdf_file, content_type='application/pdf')
            #         response['Content-Disposition'] = f'attachment; filename="{file_name}"'
            #         return response
            # else:
            #     return Response({'error': 'Report generation failed.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
