from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password

from FaceMotionMonitorApp.models.userProfile_models import Auth
User = get_user_model()

class AuthBackend(object):
    def authenticate(self, request, login=None, password=None):

        try:
            user = Auth.objects.get(login=login)
            if check_password(password, user.password):
                return user
        except Auth.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return Auth.objects.get(pk=user_id)
        except Auth.DoesNotExist:
            return None

# #     # def get_user_role(self, login):
# #     #     try:
# #     #         user = Auth.objects.get(login)
# #     #         return user.role
# #     #     except Auth.DoesNotExist:
# #     #         return None
#


# from django.contrib.auth import get_user_model
# from django.contrib.auth.hashers import check_password
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework import status
#
# from FaceMotionMonitorApp.models.userProfile_models import Auth
#
# User = get_user_model()
#
# class AuthBackend:
#     def authenticate(self, request, login=None, password=None):
#         try:
#             user = Auth.objects.get(login=login)
#             if check_password(password, user.password):
#                 return user
#         except Auth.DoesNotExist:
#             return None
#
#     def get_user(self, user_id):
#         try:
#             return Auth.objects.get(pk=user_id)
#         except Auth.DoesNotExist:
#             return None
#
