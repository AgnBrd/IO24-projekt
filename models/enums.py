from enum import Enum


class Role(Enum):
    ADMIN = 'admin'
    DOCTOR = 'doctor'
    PATIENT = 'patient'


class Sex(Enum):
    MALE = 'male'
    FEMALE = 'female'
