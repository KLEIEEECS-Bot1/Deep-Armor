from django import forms
from .models import UploadedPDF

class PDFUploadForm(forms.ModelForm):
    class Meta:
        model = UploadedPDF
        fields = ['pdf_file']
        widgets = {
            'pdf_file': forms.FileInput(attrs={'accept': 'application/pdf'})
        }