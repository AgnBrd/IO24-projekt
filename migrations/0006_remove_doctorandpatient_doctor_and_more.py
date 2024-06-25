# Generated by Django 5.0.6 on 2024-05-19 19:50

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('FaceMotionMonitorApp', '0005_remove_doctorandpatient_doctor_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='doctorandpatient',
            name='doctor',
        ),
        migrations.RemoveField(
            model_name='doctorandpatient',
            name='patient',
        ),
        migrations.AddField(
            model_name='doctorandpatient',
            name='doctor_id',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='doctor_relations', to='FaceMotionMonitorApp.doctor'),
        ),
        migrations.AddField(
            model_name='doctorandpatient',
            name='patient_id',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='patient_relations', to='FaceMotionMonitorApp.patient'),
        ),
    ]