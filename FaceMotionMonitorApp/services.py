from django.db.models import Max
from django.utils import timezone

from FaceMotionMonitorApp.models.userProfile_models import Recordings, Frames, FrameLandmarks, RefPhotoLandmarks, \
    RefPhotos, UserProfile, Auth, Doctor
from FaceMotionMonitorApp.models.userProfile_models import DoctorAndPatient, Patient, UserProfile, Reports
from FaceMotionMonitorApp.serializers import ReportsSerializer, PatientSerializer, AuthUpdateSerializer, \
    DoctorAndPatientSerializer, DoctorSerializer, AuthSerializer, UserProfileSerializer


def create_user_profile(data):
    user_profile_serializer = UserProfileSerializer(data=data)
    if user_profile_serializer.is_valid():
        return user_profile_serializer.save()
    return None, user_profile_serializer.errors


def create_auth(auth_data):
    auth_serializer = AuthSerializer(data=auth_data)
    if auth_serializer.is_valid():
        return auth_serializer.save()
    return None, auth_serializer.errors


def create_doctor(doctor_data):
    doctor_serializer = DoctorSerializer(data=doctor_data)
    if doctor_serializer.is_valid():
        return doctor_serializer.save()
    return None, doctor_serializer.errors


def add_patient_to_doctor(patient_id, doctor_id):
    patient_and_doctor_data = {
        'patient_id': patient_id,
        'doctor_id': doctor_id
    }
    patient_doctor_serializer = DoctorAndPatientSerializer(data=patient_and_doctor_data)
    if patient_doctor_serializer.is_valid():
        return patient_doctor_serializer.save()
    return None, patient_doctor_serializer.errors


def update_auth(user, new_data):
    serializer = AuthUpdateSerializer(user, data=new_data)
    if serializer.is_valid():
        return serializer.save()
    return None, serializer.errors


def delete_user(user_id):
    try:
        Auth.objects.filter(id=user_id).delete()
        patient = Patient.objects.filter(user_id=user_id).first()
        if patient:
            patient_id = patient.id
            patient.delete()
            DoctorAndPatient.objects.filter(patient_id=patient_id).delete()

        doctor = Doctor.objects.filter(user_id=user_id).first()
        if doctor:
            doctor_id = doctor.id
            doctor.delete()
            DoctorAndPatient.objects.filter(doctor_id=doctor_id).delete()

        UserProfile.objects.filter(id=user_id).delete()
        return {'message': 'User deleted successfully'}, 200
    except Exception as e:
        return {'error': 'Failed to delete user', 'details': str(e)}, 500


def get_patients_by_doctor(user_id):
    try:
        doctor = Doctor.objects.get(user_id=user_id)
        doctor_id = doctor.id
        doctor_patient_relations = DoctorAndPatient.objects.filter(doctor_id=doctor_id)
        patient_ids = doctor_patient_relations.values_list('patient_id', flat=True)
        patients = Patient.objects.filter(id__in=patient_ids).select_related('user_id')
        serializer = PatientSerializer(patients, many=True)
        return serializer.data, None
    except Exception as e:
        return None, str(e)


def get_reports_for_doctor(doctor_id, patient_id):
    if DoctorAndPatient.objects.filter(doctor_id=doctor_id, patient_id=patient_id).exists():
        reports = Reports.objects.filter(patient_id=patient_id)
        serializer = ReportsSerializer(reports, many=True)
        return serializer.data, None
    return None, 'No reports found for this patient'


def calculate_difference(landmarks_data):
    distances = [data['distance'] for data in landmarks_data]
    mouth_diff = 0
    eyebrow_diff = 0
    return mouth_diff, eyebrow_diff


def get_reports_for_patient(patient_id):
    reports = Reports.objects.filter(patient_id=patient_id)
    serializer = ReportsSerializer(reports, many=True)
    return serializer.data, None


def get_max_landmark_distance(patient_id, landmark_number):
    try:
        # Get the latest recording for the given patient
        latest_recording = Recordings.objects.filter(patient_id=patient_id).latest('date')

        # Get the frames associated with the latest recording
        frames = Frames.objects.filter(recording_id=latest_recording)

        # Get the maximum distance for the specified landmark number
        max_distance = FrameLandmarks.objects.filter(frame_id__in=frames, landmark_number=landmark_number).aggregate(
            Max('distance'))

        return max_distance
    except Recordings.DoesNotExist:
        return None  # Handle case where no recordings exist for the patient
    except Frames.DoesNotExist:
        return None  # Handle case where no frames exist for the recording
    except FrameLandmarks.DoesNotExist:
        return None  # Handle case where no landmarks exist for the frames


# Example usage
# patient_id = 1  # Replace with actual patient ID
# landmark_number = 2  # Replace with the desired landmark number
# max_distance = get_max_landmark_distance(patient_id, landmark_number)


def get_patients_for_doctor(doctor_id):
    try:
        # Pobranie rekordów z tabeli DoctorAndPatient dla danego doktora
        doctor_patients = DoctorAndPatient.objects.filter(doctor_id=doctor_id)

        # Pobranie identyfikatorów pacjentów przypisanych do danego doktora
        patient_ids = [dp.patient_id for dp in doctor_patients]

        # Pobranie danych pacjentów na podstawie ich identyfikatorów
        patients = Patient.objects.filter(id__in=patient_ids)

        # Pobranie danych użytkowników dla pacjentów
        users = UserProfile.objects.filter(id__in=[patient.user_id_id for patient in patients])

        # Stworzenie słownika, gdzie klucz to ID pacjenta, a wartość to dane pacjenta i użytkownika
        patient_data = {}
        for patient in patients:
            patient_data[patient.id] = {
                'patient_data': patient,
                'user_data': next((user for user in users if user.id == patient.user_id_id), None)
            }

        # Zwrócenie słownika
        return patient_data
    except Exception as e:
        # Obsługa wyjątku (np. gdy nie ma pacjentów przypisanych do danego doktora)
        print(f"Error occurred: {e}")
        return {}


#EXAMPLE
# patients_data = get_patients_for_doctor(doctor_id)
#
# # Wyświetlenie danych pacjentów
# for patient_id, data in patients_data.items():
#     print("Patient ID:", patient_id)
#     print("Patient Data:", data['patient_data'])
#     print("User Data:", data['user_data'])
#     print("\n")


def get_reports_for_patient(patient_id):
    try:
        # Pobranie wszystkich raportów dla danego pacjenta
        reports = Reports.objects.filter(patient_id_id=patient_id)
        # Zwrócenie raportów
        return reports
    except Exception as e:
        # Obsługa wyjątku (np. gdy nie ma raportów dla danego pacjenta)
        print(f"Error occurred: {e}")
        return []


#FOR REPORTS PATIENT DATA
def get_patient_details(patient_id):
    # Fetch the patient object based on the patient_id
    patient = Patient.objects.get(id=patient_id)
    user_id = patient.user_id_id
    # Fetch the related user profile
    user_profile = UserProfile.objects.get(id=user_id)

    # Prepare the patient details
    patient_details = {
        'name': user_profile.name,
        'surname': user_profile.surname,
        'pesel': user_profile.pesel,
        'date_of_birth': patient.date_of_birth,
        'date_of_diagnosis': patient.date_of_diagnosis,
    }

    return patient_details


#EXAMPLE
# reports = get_reports_for_patient(patient_id)
#
# # Wyświetlenie danych raportów
# for report in reports:
#     print("Report ID:", report.id)
#     print("Date:", report.date)
#     print("Difference Mouth:", report.difference_mouth)
#     print("Difference 2:", report.difference_2)
#     print("\n")


def get_ref_distances_for_landmarks(patient_id, landmark_numbers):
    try:
        # Pobranie wszystkich landmarków dla danego pacjenta
        landmarks = RefPhotoLandmarks.objects.filter(ref_photo__patient_id_id=patient_id,
                                                     landmark_number__in=landmark_numbers)

        # Stworzenie słownika, gdzie kluczem będzie numer landmarku, a wartością dystans dla tego landmarku
        distances = {}
        for landmark in landmarks:
            distances[landmark.landmark_number] = landmark.distance

        # Zwrócenie słownika z dystansami dla wybranych landmarków
        return distances
    except Exception as e:
        # Obsługa wyjątku (np. gdy nie ma danych dla danego pacjenta lub landmarków)
        print(f"Error occurred: {e}")
        return {}


#EXAMPLE
# patient_id = 1
# landmark_numbers = [1, 2, 3]
# distances = get_ref_distances_for_landmarks(patient_id, landmark_numbers)
# for landmark_number, distance in distances.items():
#     print(f"Landmark {landmark_number}: Distance = {distance}")


def get_centers_for_patient(patient_id):
    try:
        photos = RefPhotos.objects.filter(patient_id_id=patient_id)
        centers = [(photo.x_center, photo.y_center) for photo in photos]
        # Zwrócenie listy krotek z współrzędnymi x_center i y_center dla zdjęć referencyjnych
        return centers
    except Exception as e:
        print(f"Error occurred: {e}")
        return []


#for admin
def get_users_with_roles():
    try:
        users = UserProfile.objects.all()
        users_with_roles = []
        for user in users:
            auth_data = Auth.objects.filter(id=user.id).first()
            role = auth_data.role if auth_data else None
            users_with_roles.append((user, role))

        return users_with_roles

    except Exception as e:
        print(f"Error occurred: {e}")
        return []


#EXAMPLE
# users_with_roles = get_users_with_roles()
#
# for user, role in users_with_roles:
#     print("Name:", user.name)
#     print("Surname:", user.surname)
#     print("Email:", user.email)
#     print("PESEL:", user.pesel)
#     print("Role:", role)
#     print("\n")


# FOR REPORTS
def get_landmarks_for_patient(patient_id):
    landmark_numbers = [61, 291, 55, 285]
    # 61 -left mouth corner
    # 291 - right mouth corner
    # 55 - left brow (inner corner)
    # 285 - right brow (inner corner)

    try:
        # Pobierz wszystkie zdjęcia referencyjne dla danego pacjenta
        ref_photos = RefPhotos.objects.filter(patient_id__id=patient_id)

        # Pobierz odległości dla wybranych numerów landmarków
        distances = RefPhotoLandmarks.objects.filter(
            ref_photo__in=ref_photos,
            landmark_number__in=landmark_numbers
        ).values_list('distance', flat=True)

        # Zwróć listę odległości
        return list(distances)

    except Exception as e:
        # Obsługa błędów
        print(f"Error: {e}")
        return None


## FOR REPORTS
def get_data_for_reports(patient_id):
    try:
        # Pobierz raporty dla danego pacjenta
        reports = Reports.objects.filter(patient_id=patient_id)

        dates = [report.date for report in reports]
        differences_mouth = [report.difference_mouth for report in reports]
        differences_2 = [report.difference_2 for report in reports]

        return dates, differences_mouth, differences_2

    except Exception as e:

        print(f"Error: {e}")
        return [], [], []
