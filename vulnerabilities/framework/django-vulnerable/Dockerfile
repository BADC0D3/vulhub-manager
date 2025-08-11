FROM python:3.8

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV DJANGO_SETTINGS_MODULE vulnerable_app.settings

# Set work directory
WORKDIR /app

# Install dependencies
RUN pip install --upgrade pip
RUN pip install django==3.2.0 \
    djangorestframework==3.12.4 \
    django-cors-headers==3.7.0 \
    psycopg2-binary==2.9.1

# Create Django project
RUN django-admin startproject vulnerable_app .

# Create a vulnerable view with SQL injection
RUN mkdir -p vulnerable_app/views && \
    echo "from django.http import HttpResponse\n\
from django.db import connection\n\
\n\
def search(request):\n\
    query = request.GET.get('q', '')\n\
    # Vulnerable to SQL injection\n\
    with connection.cursor() as cursor:\n\
        cursor.execute(f\"SELECT * FROM users WHERE name LIKE '%{query}%'\")\n\
        results = cursor.fetchall()\n\
    return HttpResponse(str(results))\n" > vulnerable_app/views/vulnerable.py

# Update settings to allow all hosts and disable security features
RUN echo "\n\
ALLOWED_HOSTS = ['*']\n\
DEBUG = True\n\
SECURE_SSL_REDIRECT = False\n\
SESSION_COOKIE_SECURE = False\n\
CSRF_COOKIE_SECURE = False\n\
X_FRAME_OPTIONS = 'ALLOWALL'\n" >> vulnerable_app/settings.py

# Add URL patterns
RUN echo "from django.urls import path\n\
from vulnerable_app.views.vulnerable import search\n\
from django.contrib import admin\n\
\n\
urlpatterns = [\n\
    path('admin/', admin.site.urls),\n\
    path('search/', search, name='search'),\n\
]\n" > vulnerable_app/urls.py

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"] 