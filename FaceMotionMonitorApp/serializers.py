from django.contrib.auth.hashers import check_password
from rest_framework import serializers
from django.apps import apps
from django.contrib.auth.hashers import make_password
from FaceMotionMonitorApp.models import UserProfile
from FaceMotionMonitorApp.models.userProfile_models import Auth, Doctor, Patient, DoctorAndPatient, Recordings, Frames, \
    FrameLandmarks, RefPhotos, RefPhotoLandmarks, Reports


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['id', 'name', 'surname', 'email', 'pesel']


def validate_email(value):  # to check if email is taken
    if UserProfile.objects.filter(email=value).exists():
        raise serializers.ValidationError("Email already exists.")
    else:
        return False


class AuthSerializer(serializers.ModelSerializer):
    class Meta:
        model = Auth
        fields = ['id', 'login', 'password', 'role']
        extra_kwargs = {'password': {'write_only': True}}


def validate_login(value):  # to check if login is taken
    if Auth.objects.filter(login=value).exists():
        raise serializers.ValidationError("Login already exists.")
    else:
        return False


class AuthUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Auth
        fields = ['login', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_login(self, value):
        if self.instance and self.instance.login == value:
            return value
        if Auth.objects.filter(login=value).exists():
            raise serializers.ValidationError("Login already exists.")
        return value

    def update(self, instance, validated_data):
        instance.login = validated_data.get('login', instance.login)
        instance.password = make_password(validated_data.get('password', instance.password))
        instance.save()
        return instance


class DoctorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Doctor
        fields = ['id', 'pwz_pwzf', 'user_id']


def validate_pwz_pwzf(value):  # to check if pwz is taken
    if Doctor.objects.filter(pwz_pwzf=value).exists():
        raise serializers.ValidationError("PWZ_PWZF already exists.")
    else:
        return False


class PatientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Patient
        fields = ['id', 'date_of_birth', 'date_of_diagnosis', 'sex', 'user_id']

class PatientSerializer1(serializers.ModelSerializer):
    user_profile = UserProfileSerializer(source='user_id', read_only=True)

    class Meta:
        model = Patient
        fields = ['id', 'date_of_birth', 'date_of_diagnosis', 'sex', 'user_profile']
class DoctorAndPatientSerializer(serializers.ModelSerializer):
    class Meta:
        model = DoctorAndPatient
        fields = ['id', 'patient_id', 'doctor_id']
    #


def validate_pesel(value):  # to check if pesel of patient is in db
    if UserProfile.objects.filter(pesel=value).exists():
        return True
    else:
        return False


class LoginSerializer(serializers.Serializer):
    login = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    def validate(self, data):
        login = data.get('login')
        password = data.get('password')

        try:
            user = Auth.objects.get(login=login)
        except Auth.DoesNotExist:
            raise serializers.ValidationError("Invalid login credentials.")

        if not check_password(password, user.password):
            raise serializers.ValidationError("Invalid login credentials.")

        data['user'] = user
        return data




class FramesSerializer(serializers.ModelSerializer):

    class Meta:
        model = Frames
        fields = ['id', 'frame_number', 'timestamp', 'x_center', 'y_center', 'recording_id']


class FrameLandmarksSerializer(serializers.ModelSerializer):
    class Meta:
        model = FrameLandmarks
        fields = ['id', 'landmark_number', 'distance', 'frame_id']

class RecordingsSerializer(serializers.ModelSerializer):

    class Meta:
        model = Recordings
        fields = ['id', 'date', 'time', 'patient_id']


class RefPhotosSerializer(serializers.ModelSerializer):
    class Meta:
        model = RefPhotos
        fields = ['id', 'date', 'x_center', 'y_center', 'patient_id']


class RefPhotoLandmarksSerializer(serializers.ModelSerializer):
    class Meta:
        model = RefPhotoLandmarks
        fields = ['id', 'landmark_number', 'distance', 'ref_photo']


class ReportsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Reports
        fields = ['id', 'date', 'difference_mouth', 'difference_face', 'patient_id']

class ReportsSerializer1(serializers.ModelSerializer):
    class Meta:
        model = Reports
        fields = ['id', 'date', 'difference_mouth', 'difference_2']




class PatientSerializer1(serializers.ModelSerializer):
    pesel = serializers.CharField(source='user_id.pesel')  # Access pesel from related UserProfile

    class Meta:
        model = Patient
        fields = ['id', 'date_of_birth', 'date_of_diagnosis', 'sex', 'pesel']  # Include pesel in the fields

class PatientsSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='user_id.name')
    surname = serializers.CharField(source='user_id.surname')
    email = serializers.CharField(source='user_id.email')
    date_of_last_exam = serializers.SerializerMethodField()

    class Meta:
        model = Patient
        fields = ['id', 'name', 'surname', 'sex', 'email', 'date_of_last_exam']  # Include pesel in the fields
    def get_date_of_last_exam(self, obj):
        # Pobieramy najnowszy raport dla danego pacjenta
        latest_report = Reports.objects.filter(patient_id=obj.user_id).order_by('-date').first()
        if latest_report:
            return latest_report.date
        return None

