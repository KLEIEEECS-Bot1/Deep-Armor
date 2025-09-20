"""
URL configuration for phishing_analyzer project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from analyzer.views import upload_pdf, analysis_results, analysis_progress

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', upload_pdf, name='upload_pdf'),
    path('results/<int:pdf_id>/', analysis_results, name='analysis_results'),
    path('progress/<int:pdf_id>/', analysis_progress, name='analysis_progress'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)