from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import matplotlib.pyplot as plt
import numpy as np
import os
from datetime import date, datetime, timedelta
from FaceMotionMonitorApp import services, views

def make_figures(patient_id):
    # Assuming you want to retrieve data for the last 30 days
    dates, mouth, brows = services.get_data_for_reports(patient_id)

    plt.figure(figsize=(12, 8))
    plt.plot(dates, mouth, label='Mouth Corners Distance', marker='o')
    plt.xlabel('Date')
    plt.ylabel('Difference')
    plt.legend()
    mouth_fig = plt.gcf()

    plt.figure(figsize=(12, 8))
    plt.plot(dates, brows, label='Eyebrows Distance Difference', marker='x', color='orange')
    plt.xlabel('Date')
    plt.ylabel('Difference')
    plt.legend()
    eyebrows_fig = plt.gcf()

    return mouth_fig, eyebrows_fig


def distance_comparison(patient_id):
    dates, mouth, brows = services.get_data_for_reports(patient_id)

    mouth_diff_first = mouth[-1] / mouth[0] * 100
    mouth_diff_previous = mouth[-1] / mouth[-2] * 100

    eyebrows_diff_first = brows[-1] / brows[0] * 100
    eyebrows_diff_previous = brows[-1] / brows[-2] * 100

    return mouth_diff_first, mouth_diff_previous, eyebrows_diff_first, eyebrows_diff_previous


def create_report(patient_id):
    today = date.today()

    patient_data = services.get_patient_details(patient_id)
    file_name = f"{patient_data['name']}report{today}.pdf"

    # Generate figures
    mouth_fig, eyebrows_fig = make_figures(patient_id)

    # Save figures as PNG files
    mouth_fig.savefig('mouth_corners.png')
    eyebrows_fig.savefig('eyebrows.png')

    # Create PDF report
    report = canvas.Canvas(file_name, pagesize=letter)
    width, height = letter

    # Draw patient data
    report.setFont("Helvetica", 12)
    report.drawString(100, height - 50, f"Name: {patient_data['name']}")
    report.drawString(100, height - 70, f"Surname: {patient_data['surname']}")
    report.drawString(100, height - 90, f"PESEL: {patient_data['pesel']}")
    report.drawString(100, height - 110, f"Date of Birth: {patient_data['date_of_birth']}")
    report.drawString(100, height - 130, f"Date of Diagnosis: {patient_data['date_of_diagnosis']}")

    # Draw mouth figure
    report.drawString(100, height - 170, "Mouth Corners Distance")
    report.drawImage('mouth_corners.png', 100, height - 420, width=400, height=200)

    # Draw eyebrows figure
    report.drawString(100, height - 450, "Eyebrows Distance Difference")
    report.drawImage('eyebrows.png', 100, height - 700, width=400, height=200)

    # Save and clean up temporary files
    report.save()
    os.remove("mouth_corners.png")
    os.remove("eyebrows.png")

    return file_name