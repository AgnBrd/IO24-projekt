# Generated by Django 5.0.6 on 2024-05-13 20:14

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('FaceMotionMonitorApp', '0003_doctor_patient_doctorandpatient'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='patient',
            name='ref_photo',
        ),
        migrations.AddField(
            model_name='refphotos',
            name='patient_id',
            field=models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, to='FaceMotionMonitorApp.patient'),
        ),
    ]