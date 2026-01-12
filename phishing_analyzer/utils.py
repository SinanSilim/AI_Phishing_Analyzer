"""
Utility functions for the phishing analyzer
"""

import re
import socket
import logging
from urllib.parse import urlparse
from datetime import datetime
from typing import Optional, Dict, List, Any

# Configure logging
logger = logging.getLogger(__name__)


def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception as e:
        logger.error(f"Error extracting domain from {url}: {e}")
        return None


def extract_urls(text: str) -> List[str]:
    """Extract all URLs from text"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return list(set(urls))  # Remove duplicates


def extract_emails(text: str) -> List[str]:
    """Extract email addresses from text"""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    return list(set(emails))


def is_ip_address(domain: str) -> bool:
    """Check if domain is an IP address"""
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False


def calculate_domain_similarity(domain1: str, domain2: str) -> float:
    """
    Calculate similarity between two domains using Levenshtein distance
    Returns value between 0 (completely different) and 1 (identical)
    """
    def levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    distance = levenshtein_distance(domain1.lower(), domain2.lower())
    max_len = max(len(domain1), len(domain2))
    similarity = 1 - (distance / max_len) if max_len > 0 else 0
    return similarity


def check_typosquatting(domain: str, target_domains: List[str], threshold: float = 0.8) -> Dict[str, Any]:
    """
    Check if domain is potentially typosquatting a legitimate domain
    """
    # Remove common TLDs for comparison
    domain_base = re.sub(r'\.(com|org|net|edu|gov)$', '', domain)
    
    results = {
        'is_typosquatting': False,
        'target_domain': None,
        'similarity': 0.0,
        'common_tricks': []
    }
    
    for target in target_domains:
        target_base = re.sub(r'\.(com|org|net|edu|gov)$', '', target)
        similarity = calculate_domain_similarity(domain_base, target_base)
        
        if similarity > results['similarity']:
            results['similarity'] = similarity
            results['target_domain'] = target
            
        if similarity >= threshold and similarity < 1.0:
            results['is_typosquatting'] = True
            results['target_domain'] = target
    
    # Check for common typosquatting tricks
    tricks = []
    if '1' in domain_base or '0' in domain_base:
        tricks.append('number_substitution')
    if any(char in domain_base for char in ['-', '_']):
        tricks.append('separator_addition')
    if len(domain_base) > 20:
        tricks.append('domain_elongation')
    
    results['common_tricks'] = tricks
    
    return results


def check_suspicious_tld(domain: str, suspicious_tlds: List[str]) -> bool:
    """Check if domain uses a suspicious TLD"""
    domain_lower = domain.lower()
    return any(domain_lower.endswith(tld) for tld in suspicious_tlds)


def extract_domain_info(url: str) -> Dict[str, str]:
    """Extract detailed information from URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        
        return {
            'scheme': parsed.scheme,
            'domain': parsed.netloc.lower(),
            'path': parsed.path,
            'params': parsed.params,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'full_url': url
        }
    except Exception as e:
        logger.error(f"Error parsing URL {url}: {e}")
        return {}


def normalize_url(url: str) -> str:
    """Normalize URL for consistent processing"""
    url = url.strip().lower()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of text (higher = more random/suspicious)
    Used to detect randomly generated domain names
    """
    if not text:
        return 0.0
    
    from collections import Counter
    import math
    
    counts = Counter(text)
    total = len(text)
    entropy = -sum((count/total) * math.log2(count/total) for count in counts.values())
    return entropy


def age_in_days(date: datetime) -> int:
    """Calculate age in days from a datetime object"""
    return (datetime.now() - date).days


def format_risk_level(score: int) -> str:
    """Format risk score into categorical level"""
    if score <= 25:
        return "LOW"
    elif score <= 50:
        return "MEDIUM"
    elif score <= 75:
        return "HIGH"
    else:
        return "CRITICAL"


def sanitize_input(text: str, max_length: int = 10000) -> str:
    """Sanitize user input to prevent issues"""
    if not isinstance(text, str):
        text = str(text)
    
    # Truncate if too long
    text = text[:max_length]
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    return text.strip()


def create_summary(results: Dict[str, Any]) -> str:
    """Create a human-readable summary of analysis results"""
    risk_score = results.get('risk_score', 0)
    risk_level = format_risk_level(risk_score)
    
    summary = f"Risk Score: {risk_score}/100 ({risk_level})\n"
    
    threat_indicators = results.get('threat_indicators', [])
    if threat_indicators:
        summary += f"\nThreat Indicators ({len(threat_indicators)}):\n"
        for indicator in threat_indicators[:10]:  # Show top 10
            summary += f"  • {indicator}\n"
    
    recommendations = results.get('recommendations', [])
    if recommendations:
        summary += f"\nRecommendations:\n"
        for rec in recommendations:
            summary += f"  • {rec}\n"
    
    return summary


def load_wordlist(filename: str) -> List[str]:
    """Load a wordlist from file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        logger.warning(f"Wordlist file not found: {filename}")
        return []


def cache_result(cache_dict: Dict, key: str, value: Any, ttl: int = 3600):
    """Simple cache implementation with TTL"""
    cache_dict[key] = {
        'value': value,
        'timestamp': datetime.now(),
        'ttl': ttl
    }


def get_cached_result(cache_dict: Dict, key: str) -> Optional[Any]:
    """Retrieve cached result if still valid"""
    if key not in cache_dict:
        return None
    
    cached = cache_dict[key]
    age = (datetime.now() - cached['timestamp']).total_seconds()
    
    if age < cached['ttl']:
        return cached['value']
    else:
        # Expired, remove from cache
        del cache_dict[key]
        return None
