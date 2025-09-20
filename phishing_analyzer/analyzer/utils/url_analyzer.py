import requests
import tldextract
import whois
import idna
from difflib import SequenceMatcher
from urllib.parse import urlparse


OFFICIAL_DOMAINS = {
    "amazon": "amazon.com",
    "google": "google.com",
    "gmail": "gmail.com",
    "deeparmor": "deeparmor.com",
    "facebook": "facebook.com",
    "bing": "bing.com",
    "flipkart": "flipkart.com"
}

SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.info', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw']


def string_similarity(a, b):
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()

def normalize_domain(domain: str) -> str:
    try:
        return idna.encode(domain).decode('ascii')
    except:
        return domain

def is_suspicious_tld(domain):
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

def check_redirects(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        return len(response.history) > 0, response.url
    except:
        return False, url

def check_open_redirect(url):
    test_params = ['url', 'redirect', 'next', 'return', 'r']
    for param in test_params:
        test_url = f"{url}?{param}=https://example.com"
        try:
            response = requests.get(test_url, timeout=5, allow_redirects=False, verify=False)
            if 300 <= response.status_code < 400 and 'example.com' in response.headers.get('Location', ''):
                return True, param
        except:
            continue
    return False, None


def check_domain_impersonation(domain):
    known_brands = {
        'amazon': ['amazon', 'amzn'],
        'google': ['google', 'gogle', 'gooogle'],
        'gmail': ['gmail', 'gmaiil', 'gmaill'],
        'deeparmor': ['deeparmor'],
        'facebook': ['facebook', 'facebok'],
        'flipkart': ['flipkart', 'fliipkart', 'fiipkart']
    }

    domain_lower = domain.lower()
    for brand, variations in known_brands.items():
        if domain_lower == brand:
            return False, None, None, 1.0
        for variation in variations:
            if variation != brand and variation in domain_lower:
                similarity = string_similarity(domain_lower, brand)
                if 0.7 < similarity < 0.99:
                    return True, brand, f"typosquatting_{variation}", similarity
            if brand.startswith(domain_lower):
                similarity = string_similarity(domain_lower, brand)
                return True, brand, "missing_characters", similarity
            if len(domain_lower) > len(brand) + 2 and brand in domain_lower:
                similarity = string_similarity(domain_lower, brand)
                return True, brand, "extra_characters", similarity
    return False, None, None, 0


def check_redirect_path_impersonation(original_domain, final_url, known_brands):
    parsed = urlparse(final_url)
    path = parsed.path.lower()
    final_domain = parsed.netloc.lower()
    for brand in known_brands:
        if brand in path and brand not in final_domain:
            similarity = string_similarity(brand, path)
            return True, brand, "redirect_path_contains_brand", similarity
    return False, None, None, 0


def compare_domains(url, official_domain):
    extracted = tldextract.extract(url)
    found_domain = f"{extracted.domain}.{extracted.suffix}".lower()
    official_domain = official_domain.lower()
    similarity = string_similarity(found_domain, official_domain)
    if found_domain == official_domain:
        return "exact_match", similarity
    elif similarity > 0.85:
        return "typosquatting_suspected", similarity
    else:
        return "no_match", similarity

def verify_company_domains(mentioned_companies, urls):
    results = {
        "companies": [],
        "total_matches": 0,
        "total_suspicious": 0,
        "verification_summary": ""
    }

    for company in mentioned_companies:
        official_domain = OFFICIAL_DOMAINS.get(company.lower())
        if not official_domain:
            continue

        company_data = {
            "name": company,
            "official_domain": official_domain,
            "domain_info": {
                "domain": official_domain,
                "subdomain": "",
                "registered_domain": official_domain,
                "suffix": official_domain.split('.')[-1]
            },
            "url_matches": [],
            "suspicious_urls": []
        }

        for url in urls:
            comparison, similarity = compare_domains(url, official_domain)
            entry = {"url": url, "similarity": similarity, "status": comparison}
            if comparison == "exact_match":
                company_data["url_matches"].append(entry)
                results["total_matches"] += 1
            else:
                company_data["suspicious_urls"].append(entry)
                if comparison == "typosquatting_suspected":
                    results["total_suspicious"] += 1

        results["companies"].append(company_data)

    if results["total_suspicious"] > 0:
        results["verification_summary"] = f"WARNING: {results['total_suspicious']} suspicious URLs found"
    elif results["total_matches"] > 0:
        results["verification_summary"] = f"OK: {results['total_matches']} URLs match official domains"
    else:
        results["verification_summary"] = "No domain verification possible"

    return results


def analyze_url(url, mentioned_companies=None):
    result = {
        'is_suspicious': False,
        'reasons': [],
        'redirects': False,
        'final_url': url,
        'open_redirect': False,
        'open_redirect_param': None,
        'domain_info': {},
        'impersonation_analysis': {},
        'company_verification': {}
    }

    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        normalized = normalize_domain(domain)

        result['domain_info'] = {
            'domain': domain,
            'normalized_domain': normalized,
            'subdomain': extracted.subdomain,
            'tld': extracted.suffix
        }

        # Suspicious TLD
        if is_suspicious_tld(domain):
            result['is_suspicious'] = True
            result['reasons'].append('suspicious_tld')

        # Domain impersonation
        is_impersonating, brand, reason, similarity = check_domain_impersonation(extracted.domain)
        if is_impersonating:
            result['is_suspicious'] = True
            result['reasons'].append(reason)
            result['impersonation_analysis'] = {
                'original_brand': brand,
                'detected_domain': extracted.domain,
                'reason': reason,
                'similarity_score': similarity
            }

        # Company verification
        if mentioned_companies:
            result['company_verification'] = verify_company_domains(mentioned_companies, [url])
            for company in result['company_verification']['companies']:
                for su in company['suspicious_urls']:
                    if su['status'] == 'typosquatting_suspected':
                        result['is_suspicious'] = True
                        if su['status'] not in result['reasons']:
                            result['reasons'].append(su['status'])

        # Redirects
        has_redirects, final_url = check_redirects(url)
        result['redirects'] = has_redirects
        result['final_url'] = final_url

        # Open redirect
        has_open_redirect, param = check_open_redirect(url)
        result['open_redirect'] = has_open_redirect
        result['open_redirect_param'] = param

        # Check redirect path for brand impersonation
        known_brands = list(OFFICIAL_DOMAINS.keys())
        if has_redirects:
            rp_flag, rp_brand, rp_reason, rp_similarity = check_redirect_path_impersonation(
                extracted.domain.lower(),
                final_url,
                known_brands
            )
            if rp_flag:
                result['is_suspicious'] = True
                result['reasons'].append(rp_reason)
                result['impersonation_analysis'] = {
                    'original_brand': rp_brand,
                    'detected_domain': urlparse(final_url).netloc,
                    'reason': rp_reason,
                    'similarity_score': rp_similarity
                }

        # WHOIS for suspicious domains
        if result['is_suspicious']:
            try:
                whois_data = whois.whois(normalized)
                result['domain_info']['whois'] = {
                    'creation_date': str(whois_data.creation_date),
                    'expiration_date': str(whois_data.expiration_date),
                    'registrar': whois_data.registrar,
                    'country': whois_data.country,
                }
            except:
                result['domain_info']['whois'] = {'error': 'Unable to fetch WHOIS data'}
        else:
            result['domain_info']['whois'] = {'skipped': 'Domain not suspicious'}

    except Exception as e:
        result['error'] = str(e)
        result['is_suspicious'] = True

    return result
