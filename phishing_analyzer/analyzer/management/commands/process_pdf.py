import os
from django.core.management.base import BaseCommand
from analyzer.models import UploadedPDF, ExtractedURL, ExtractedForm, CompanyName, AnalysisResult
from analyzer.utils.pdf_parser import extract_text_from_pdf, extract_urls_from_text, extract_forms_from_text, extract_companies_from_text
from analyzer.utils.url_analyzer import analyze_url as analyze_urls_util
from analyzer.utils.form_analyzer import analyze_forms as analyze_forms_util
from analyzer.utils.company_extractor import verify_company_domains

class Command(BaseCommand):
    help = 'Process uploaded PDF for phishing analysis'
    
    def add_arguments(self, parser):
        parser.add_argument('pdf_id', type=int)
    
    def handle(self, *args, **options):
        pdf_id = options['pdf_id']
        pdf = UploadedPDF.objects.get(id=pdf_id)
        
        # Extract text from PDF
        pdf_path = pdf.pdf_file.path
        text = extract_text_from_pdf(pdf_path)
        
        # Extract URLs
        raw_urls = extract_urls_from_text(text)
        url_analysis = [analyze_urls_util(url, mentioned_companies=extract_companies_from_text(text)) for url in raw_urls]
        
        high_risk_indicators = 0
        suspicious_urls_count = 0
        
        for i, url in enumerate(raw_urls):
            analysis = url_analysis[i]
            
            # Consider URL suspicious if flagged by analyze_url or impersonation_analysis
            is_suspicious = analysis.get('is_suspicious', False) or bool(analysis.get('impersonation_analysis'))
            if is_suspicious:
                high_risk_indicators += 1
                suspicious_urls_count += 1
            
            ExtractedURL.objects.create(
                pdf=pdf,
                url=url,
                domain=analysis.get('domain_info', {}).get('domain', ''),
                is_suspicious=is_suspicious,
                security_checks=analysis
            )
        
        # Extract forms
        raw_forms = extract_forms_from_text(text)
        form_analysis = analyze_forms_util(raw_forms)
        
        phishing_forms_count = 0
        for i, form in enumerate(raw_forms):
            analysis = form_analysis[i]
            is_phishing = analysis.get('is_phishing', False)
            if is_phishing:
                phishing_forms_count += 1
            
            ExtractedForm.objects.create(
                pdf=pdf,
                form_action=form['action'],
                form_method=form.get('method', 'post'),
                form_fields=analysis.get('fields', []),
                is_phishing=is_phishing,
                analysis_results=analysis
            )
        
        # Extract company names
        companies = extract_companies_from_text(text)
        for company in companies:
            CompanyName.objects.create(
                pdf=pdf,
                name=company,
                context=text[:200]
            )
        
        # Verify company domains against found URLs
        company_verification = verify_company_domains(companies, raw_urls)
        
        # Compute overall analysis
        total_indicators = len(raw_urls) + len(raw_forms)
        
        if total_indicators == 0:
            verdict = 'legitimate'
            confidence = 100.0
        else:
            # Base risk score
            risk_score = (suspicious_urls_count * 3 + phishing_forms_count * 4 + high_risk_indicators * 5) / max(1, total_indicators * 4)
            
            # Check for urgency keywords
            urgency_keywords = [
                'urgent', 'immediately', 'security alert', 'verify now', 'action required', 
                'suspended', 'locked', 'limited time', 'congratulations', 'you won', 'prize'
            ]
            urgency_count = sum(1 for keyword in urgency_keywords if keyword.lower() in text.lower())
            
            # Increase risk score based on urgency
            risk_score = min(1.0, risk_score + (urgency_count * 0.1))
            
            if risk_score > 0.7:
                verdict = 'phishing'
            elif risk_score > 0.4:
                verdict = 'suspicious'
            else:
                verdict = 'legitimate'
                
            confidence = round(min(100.0, risk_score * 100), 1)
        
        # Extract brand mismatches
        brand_mismatches = company_verification.get("mismatches", [])
        
        AnalysisResult.objects.create(
            pdf=pdf,
            overall_verdict=verdict,
            confidence_score=confidence,
            details={
                'suspicious_urls': suspicious_urls_count,
                'phishing_forms': phishing_forms_count,
                'high_risk_indicators': high_risk_indicators,
                'brand_url_mismatches': brand_mismatches,
                'urgency_keywords_found': urgency_count,
                'total_urls': len(raw_urls),
                'total_forms': len(raw_forms),
                'mentioned_brands': companies,
                'extracted_text_preview': text[:500] + '...' if len(text) > 500 else text
            },
            company_verification=company_verification
        )
        
        self.stdout.write(self.style.SUCCESS(f'Successfully processed PDF {pdf_id}'))
