from django import forms
from FaceMotionMonitorApp.models.userProfile_models import Doctor, UserProfile

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['name', 'surname', 'email', 'pesel']

class DoctorRegistrationForm(forms.ModelForm):
    user_profile = UserProfileForm()

    class Meta:
        model = Doctor
        fields = ['pwz_pwzf', 'user_id']

    def save(self, commit=True):
        user_profile = self.fields['user_profile'].save(commit=commit)
        self.instance.user_id = user_profile
        return super().save(commit=commit)
