import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import random
import string

def generate_gibberish_data(form_fields):
    data = {}
    for field in form_fields:
        if field.get('type') in ['text', 'email', 'password', 'textarea']:
            data[field['name']] = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        elif field.get('type') in ['checkbox', 'radio']:
            data[field['name']] = 'on'
        elif field.get('type') == 'select':
            data[field['name']] = '1'
    return data

def extract_form_fields(form_html):
    soup = BeautifulSoup(form_html, 'html.parser')
    fields = []
    
    for input_tag in soup.find_all(['input', 'textarea', 'select']):
        field_info = {
            'name': input_tag.get('name', ''),
            'type': input_tag.get('type', 'text'),
            'required': input_tag.get('required', False)
        }
        fields.append(field_info)
    
    return fields

def submit_form(form_action, form_method, form_fields):
    data = generate_gibberish_data(form_fields)
    
    try:
        if form_method.lower() == 'get':
            response = requests.get(form_action, params=data, timeout=10)
        else:
            response = requests.post(form_action, data=data, timeout=10)
        
        return {
            'submitted': True,
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'response_size': len(response.content),
            'redirected': len(response.history) > 0,
            'final_url': response.url
        }
    except Exception as e:
        return {
            'submitted': False,
            'error': str(e)
        }

def analyze_form(form_html, form_action, form_method):
    fields = extract_form_fields(form_html)
    submission_result = submit_form(form_action, form_method, fields)
    
    # Check if form submits to a different domain
    action_domain = urlparse(form_action).netloc
    final_domain = urlparse(submission_result.get('final_url', '')).netloc if submission_result.get('submitted') else ''
    
    is_suspicious = action_domain != final_domain and final_domain != ''
    
    return {
        'fields': fields,
        'submission_result': submission_result,
        'domain_mismatch': is_suspicious,
        'is_phishing': is_suspicious
    }

def analyze_forms(forms_data):
    results = []
    for form in forms_data:
        result = analyze_form(form['html'], form['action'], form.get('method', 'post'))
        results.append(result)
    return results