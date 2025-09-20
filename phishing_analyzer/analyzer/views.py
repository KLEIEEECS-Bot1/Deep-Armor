import os
import threading
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.core.management import call_command
from .forms import PDFUploadForm
from .models import UploadedPDF, ExtractedURL, ExtractedForm, CompanyName, AnalysisResult

def process_pdf_background(pdf_id):
    """
    Process PDF in background thread
    """
    call_command('process_pdf', str(pdf_id))

@login_required
def upload_pdf(request):
    if request.method == 'POST':
        form = PDFUploadForm(request.POST, request.FILES)
        if form.is_valid():
            pdf = form.save(commit=False)
            pdf.user = request.user
            pdf.original_filename = request.FILES['pdf_file'].name
            pdf.save()
            
            # Process the PDF in background thread
            thread = threading.Thread(target=process_pdf_background, args=(pdf.id,))
            thread.daemon = True
            thread.start()
            
            return redirect('analysis_results', pdf_id=pdf.id)
    else:
        form = PDFUploadForm()
    return render(request, 'upload.html', {'form': form})

@login_required
def analysis_results(request, pdf_id):
    try:
        pdf = UploadedPDF.objects.get(id=pdf_id, user=request.user)
        analysis = AnalysisResult.objects.filter(pdf=pdf).first()
        urls = ExtractedURL.objects.filter(pdf=pdf)
        forms = ExtractedForm.objects.filter(pdf=pdf)
        companies = CompanyName.objects.filter(pdf=pdf)
        
        context = {
            'pdf': pdf,
            'analysis': analysis,
            'urls': urls,
            'forms': forms,
            'companies': companies,
        }
        
        return render(request, 'results.html', context)
    except UploadedPDF.DoesNotExist:
        return redirect('upload_pdf')

@login_required
def analysis_progress(request, pdf_id):
    try:
        pdf = UploadedPDF.objects.get(id=pdf_id, user=request.user)
        analysis = AnalysisResult.objects.filter(pdf=pdf).first()
        
        if analysis:
            return JsonResponse({'status': 'complete', 'result_id': analysis.id})
        else:
            # Check if processing has started
            urls_count = ExtractedURL.objects.filter(pdf=pdf).count()
            forms_count = ExtractedForm.objects.filter(pdf=pdf).count()
            
            if urls_count > 0 or forms_count > 0:
                progress = min(50 + (urls_count + forms_count) * 10, 90)
                return JsonResponse({'status': 'processing', 'progress': f'{progress}%'})
            else:
                return JsonResponse({'status': 'queued', 'progress': '0%'})
    except UploadedPDF.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'PDF not found'})
    
    