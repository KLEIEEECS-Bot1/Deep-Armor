import io
from pdfminer.high_level import extract_text
from urlextract import URLExtract
import re
import idna

def extract_text_from_pdf(pdf_path):
    return extract_text(pdf_path)

def extract_urls_from_text(text):
    extractor = URLExtract()
    urls = extractor.find_urls(text)
    return list(set(urls))

def extract_forms_from_text(text):
    forms = []
    form_patterns = [
        r'<form[^>]*>(.*?)</form>',
        r'action=["\'](.*?)["\']',
        r'(?:login|signin|sign-in|log-in|register|signup|sign-up)[\s\S]{1,200}?(?:http|www)',
    ]
    
    for pattern in form_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            if 'http' in match:
                # Extract URL from the match
                url_match = re.search(r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+)', match)
                if url_match:
                    forms.append({'html': match if len(match) > 20 else 'Form detected', 'action': url_match.group(1)})
    
    return forms

def extract_companies_from_text(text):
    companies = []
    patterns = [
        r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(?:Inc|LLC|Ltd|Corp|Corporation|Company|Limited)',
        r'@([a-zA-Z0-9]+)\.(com|org|net|edu|gov|co\.\w{2})',
        r'\b(Amazon|Google|Facebook|Microsoft|Apple|PayPal|Netflix|Twitter|Instagram|Gmail|Yahoo|Outlook|LinkedIn|Bank of America|Wells Fargo|Chase|Citi)\b',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                company = match[0]
            else:
                company = match
            
            # Basic filtering
            if len(company) > 2 and company.lower() not in ['the', 'and', 'for', 'you', 'we', 'our']:
                companies.append(company)
    
    return list(set(companies))