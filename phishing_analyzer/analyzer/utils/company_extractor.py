import difflib
import logging
import tldextract
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

def find_company_domain(company_name):
    """Try to find official domain via simple search"""
    query = company_name + " official site"
    search_url = f"https://www.bing.com/search?q={query}"
    
    try:
        response = requests.get(search_url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            result = soup.find("li", {"class": "b_algo"})
            if result:
                link = result.find("a")["href"]
                extracted = tldextract.extract(link)
                return f"{extracted.domain}.{extracted.suffix}"
    except Exception as e:
        logger.warning(f"Domain search failed for {company_name}: {e}")
    
    return None

def get_company_domain_info(domain):
    """Return parsed info about domain"""
    extracted = tldextract.extract(domain)
    return {
        "domain": f"{extracted.domain}.{extracted.suffix}",
        "subdomain": extracted.subdomain,
        "registered_domain": extracted.registered_domain,
        "suffix": extracted.suffix
    }

def compare_domains(found_url, official_domain):
    """Compare found URL with official domain"""
    found = tldextract.extract(found_url)
    official = tldextract.extract(official_domain)
    
    found_domain = f"{found.domain}.{found.suffix}"
    official_domain = f"{official.domain}.{official.suffix}"
    
    similarity = difflib.SequenceMatcher(None, found_domain, official_domain).ratio()
    
    if found_domain == official_domain:
        return "exact_match", similarity
    elif similarity > 0.7:
        return "typosquatting_suspected", similarity
    else:
        return "no_match", similarity

def verify_company_domains(mentioned_companies, found_urls):
    """Main function to verify all company domains"""
    results = {
        "companies": [],
        "total_matches": 0,
        "total_suspicious": 0,
        "verification_summary": ""
    }
    
    for company in mentioned_companies:
        logger.info(f"Searching for domain of: {company}")
        official_domain = find_company_domain(company)
        
        if official_domain:
            logger.info(f"Found official domain for {company}: {official_domain}")
            domain_info = get_company_domain_info(official_domain)
            
            company_data = {
                "name": company,
                "official_domain": official_domain,
                "domain_info": domain_info,
                "url_matches": [],
                "suspicious_urls": []
            }
            
            for url in found_urls:
                comparison, similarity = compare_domains(url, official_domain)
                if comparison == "exact_match":
                    company_data["url_matches"].append({
                        "url": url,
                        "similarity": similarity,
                        "status": "match"
                    })
                    results["total_matches"] += 1
                else:
                    company_data["suspicious_urls"].append({
                        "url": url,
                        "similarity": similarity,
                        "status": comparison
                    })
                    results["total_suspicious"] += 1
            
            results["companies"].append(company_data)
    
    if results["total_suspicious"] > 0:
        results["verification_summary"] = f"WARNING: {results['total_suspicious']} suspicious URLs found"
    elif results["total_matches"] > 0:
        results["verification_summary"] = f"OK: {results['total_matches']} URLs match official domains"
    else:
        results["verification_summary"] = "No domain verification possible"
    
    return results


import tldextract

def normalize_domain(url_or_domain: str) -> str:
    """
    Normalize a URL or domain into its registered domain form.
    Example: 
        https://login.paypa1.com -> paypa1.com
        www.google.co.uk -> google.co.uk
    """
    extracted = tldextract.extract(url_or_domain)
    if not extracted.suffix:
        return extracted.domain
    return f"{extracted.domain}.{extracted.suffix}"
