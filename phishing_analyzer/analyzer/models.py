from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import User

class UploadedPDF(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    pdf_file = models.FileField(upload_to='pdfs/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    original_filename = models.CharField(max_length=255)

class ExtractedURL(models.Model):
    pdf = models.ForeignKey(UploadedPDF, on_delete=models.CASCADE, related_name='urls')
    url = models.URLField(max_length=2000)
    domain = models.CharField(max_length=255)
    is_suspicious = models.BooleanField(default=False)
    security_checks = models.JSONField(default=dict)

class ExtractedForm(models.Model):
    pdf = models.ForeignKey(UploadedPDF, on_delete=models.CASCADE, related_name='forms')
    form_action = models.URLField(max_length=2000)
    form_method = models.CharField(max_length=10)
    form_fields = models.JSONField()
    is_phishing = models.BooleanField(default=False)
    analysis_results = models.JSONField(default=dict)

class CompanyName(models.Model):
    pdf = models.ForeignKey(UploadedPDF, on_delete=models.CASCADE, related_name='companies')
    name = models.CharField(max_length=255)
    official_domain = models.CharField(max_length=255, blank=True, null=True)
    domain_info = models.JSONField(default=dict)
    context = models.TextField()
    verified_at = models.DateTimeField(auto_now_add=True)

class AnalysisResult(models.Model):
    pdf = models.ForeignKey(UploadedPDF, on_delete=models.CASCADE, related_name='analysis_results')
    overall_verdict = models.CharField(max_length=50)
    confidence_score = models.FloatField()
    details = models.JSONField()
    company_verification = models.JSONField(default=dict)  # Add this field
    analyzed_at = models.DateTimeField(auto_now_add=True)