# In views.py of your Django app (e.g., frontend/views.py)
from django.shortcuts import render

def index(request):
    return render(request, 'index.html')
