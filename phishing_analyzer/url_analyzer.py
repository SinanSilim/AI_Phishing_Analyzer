"""
URL Analyzer Module
Performs comprehensive analysis of URLs for phishing indicators
"""

import ssl
import socket
import whois
import dns.resolver
import requests
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
import logging
import tldextract
import validators

from .utils import (
    extract_domain,
    is_ip_address,
    check_typosquatting,
    check_suspicious_tld,
    calculate_entropy,
    age_in_days,
    normalize_url
)

logger = logging.getLogger(__name__)


class URLAnalyzer:
    """Analyzes URLs for phishing indicators"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize URL Analyzer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.timeout = config.get('ssl_check_timeout', 10)
        self.whois_timeout = config.get('whois_timeout', 15)
        self.dns_timeout = config.get('dns_timeout', 10)
        
        # Load configuration values
        self.suspicious_tlds = config.get('suspicious_tlds', [])
        self.typosquat_targets = config.get('typosquat_targets', [])
        self.trusted_domains = config.get('trusted_domains', [])
        
        # Feature flags
        self.enable_ssl_check = config.get('enable_ssl_check', True)
        self.enable_whois_check = config.get('enable_whois_check', True)
        self.enable_dns_check = config.get('enable_dns_check', True)
        self.enable_blacklist_check = config.get('enable_blacklist_check', True)
        
        # Cache for results
        self.cache = {}
    
    def analyze(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive URL analysis
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        logger.info(f"Analyzing URL: {url}")
        
        # Normalize URL
        url = normalize_url(url)
        domain = extract_domain(url)
        
        if not domain:
            return {
                'error': 'Invalid URL',
                'risk_score': 100,
                'threat_indicators': ['Invalid or malformed URL']
            }
        
        results = {
            'url': url,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'checks_performed': [],
            'threat_indicators': [],
            'safe_indicators': [],
            'details': {}
        }
        
        # Check if domain is in trusted list
        if domain in self.trusted_domains:
            results['safe_indicators'].append(f'Domain {domain} is in trusted list')
            results['details']['trusted'] = True
            results['risk_score'] = 0
            return results
        
        # Perform various checks
        self._check_url_structure(url, domain, results)
        
        if self.enable_ssl_check:
            self._check_ssl_certificate(domain, results)
            results['checks_performed'].append('SSL Certificate')
        
        if self.enable_whois_check:
            self._check_domain_age(domain, results)
            results['checks_performed'].append('WHOIS/Domain Age')
        
        if self.enable_dns_check:
            self._check_dns_records(domain, results)
            results['checks_performed'].append('DNS Records')
        
        if self.enable_blacklist_check:
            self._check_blacklists(domain, results)
            results['checks_performed'].append('Blacklist Check')
        
        self._check_typosquatting(domain, results)
        results['checks_performed'].append('Typosquatting Detection')
        
        # Calculate component score
        results['url_risk_score'] = self._calculate_url_risk(results)
        
        return results
    
    def _check_url_structure(self, url: str, domain: str, results: Dict):
        """Check URL structure for suspicious patterns"""
        logger.debug(f"Checking URL structure for: {url}")
        
        details = {}
        
        # Check if URL uses HTTPS
        if url.startswith('https://'):
            results['safe_indicators'].append('Uses HTTPS protocol')
            details['https'] = True
        else:
            results['threat_indicators'].append('Uses insecure HTTP protocol')
            details['https'] = False
        
        # Check if domain is an IP address
        if is_ip_address(domain):
            results['threat_indicators'].append('Domain is an IP address (highly suspicious)')
            details['is_ip'] = True
        else:
            details['is_ip'] = False
        
        # Check for suspicious TLD
        if check_suspicious_tld(domain, self.suspicious_tlds):
            results['threat_indicators'].append(f'Uses suspicious TLD')
            details['suspicious_tld'] = True
        
        # Check URL length (phishing URLs are often very long)
        if len(url) > 100:
            results['threat_indicators'].append(f'Unusually long URL ({len(url)} characters)')
            details['long_url'] = True
        
        # Check for @ symbol (can hide real domain)
        if '@' in url:
            results['threat_indicators'].append('URL contains @ symbol (domain masking)')
            details['contains_at'] = True
        
        # Check for double slashes in path
        parsed = urlparse(url)
        if '//' in parsed.path:
            results['threat_indicators'].append('URL contains double slashes in path')
            details['double_slash'] = True
        
        # Check subdomain count (many subdomains can be suspicious)
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            results['threat_indicators'].append(f'Excessive subdomains ({subdomain_count})')
            details['subdomain_count'] = subdomain_count
        
        # Check for suspicious keywords in URL
        suspicious_keywords = ['verify', 'secure', 'account', 'login', 'banking', 'update', 'confirm']
        found_keywords = [kw for kw in suspicious_keywords if kw in url.lower()]
        if found_keywords:
            results['threat_indicators'].append(f'Contains suspicious keywords: {", ".join(found_keywords)}')
            details['suspicious_keywords'] = found_keywords
        
        # Check entropy of domain (random strings are suspicious)
        entropy = calculate_entropy(domain.split('.')[0])  # Check main domain part
        if entropy > 4.0:  # High entropy indicates random string
            results['threat_indicators'].append(f'High entropy domain name (possibly random): {entropy:.2f}')
            details['entropy'] = entropy
        
        # Check for common phishing patterns
        if any(pattern in url.lower() for pattern in ['signin', 'webscr', 'cgi-bin', 'confirm']):
            results['threat_indicators'].append('Contains common phishing URL patterns')
            details['phishing_patterns'] = True
        
        results['details']['url_structure'] = details
    
    def _check_ssl_certificate(self, domain: str, results: Dict):
        """Check SSL certificate validity"""
        logger.debug(f"Checking SSL certificate for: {domain}")
        
        details = {
            'valid': False,
            'issuer': None,
            'expiration': None,
            'days_until_expiry': None
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Certificate is valid
                    details['valid'] = True
                    results['safe_indicators'].append('Valid SSL certificate')
                    
                    # Check issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    details['issuer'] = issuer.get('organizationName', 'Unknown')
                    
                    # Check expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        details['expiration'] = expiry_date.isoformat()
                        days_until_expiry = (expiry_date - datetime.now()).days
                        details['days_until_expiry'] = days_until_expiry
                        
                        if days_until_expiry < 30:
                            results['threat_indicators'].append(f'SSL certificate expires soon ({days_until_expiry} days)')
                        elif days_until_expiry < 0:
                            results['threat_indicators'].append('SSL certificate has expired')
                            details['valid'] = False
                    
                    # Check if it's a free/basic certificate (can be suspicious)
                    if "Let's Encrypt" in details['issuer']:
                        details['is_free_cert'] = True
                    
        except ssl.SSLError as e:
            results['threat_indicators'].append(f'SSL certificate error: {str(e)[:100]}')
            details['error'] = str(e)
        except socket.timeout:
            logger.warning(f"Timeout checking SSL for {domain}")
            details['error'] = 'Timeout'
        except Exception as e:
            logger.error(f"Error checking SSL for {domain}: {e}")
            results['threat_indicators'].append('No valid SSL certificate')
            details['error'] = str(e)
        
        results['details']['ssl_certificate'] = details
    
    def _check_domain_age(self, domain: str, results: Dict):
        """Check domain registration age using WHOIS"""
        logger.debug(f"Checking domain age for: {domain}")
        
        details = {
            'registration_date': None,
            'age_days': None,
            'registrar': None
        }
        
        try:
            w = whois.whois(domain)
            
            # Get registration date
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                details['registration_date'] = creation_date.isoformat() if hasattr(creation_date, 'isoformat') else str(creation_date)
                age_days = age_in_days(creation_date)
                details['age_days'] = age_days
                
                # Evaluate age
                domain_age_config = self.config.get('domain_age', {})
                very_new = domain_age_config.get('very_new', 7)
                new = domain_age_config.get('new', 30)
                established = domain_age_config.get('established', 180)
                
                if age_days < very_new:
                    results['threat_indicators'].append(f'Domain registered only {age_days} days ago (very suspicious)')
                elif age_days < new:
                    results['threat_indicators'].append(f'Domain registered {age_days} days ago (suspicious)')
                elif age_days < established:
                    results['threat_indicators'].append(f'Domain is relatively new ({age_days} days old)')
                else:
                    results['safe_indicators'].append(f'Domain is well-established ({age_days} days old)')
            
            # Get registrar info
            if hasattr(w, 'registrar') and w.registrar:
                details['registrar'] = w.registrar
            
            # Check if domain info is hidden (privacy protection)
            if hasattr(w, 'emails') and not w.emails:
                results['threat_indicators'].append('WHOIS information hidden/protected')
                details['privacy_protected'] = True
            
        except Exception as e:
            logger.warning(f"Error checking WHOIS for {domain}: {e}")
            results['threat_indicators'].append('Unable to retrieve domain registration information')
            details['error'] = str(e)
        
        results['details']['domain_age'] = details
    
    def _check_dns_records(self, domain: str, results: Dict):
        """Check DNS records for suspicious patterns"""
        logger.debug(f"Checking DNS records for: {domain}")
        
        details = {
            'has_mx': False,
            'has_a': False,
            'mx_records': [],
            'a_records': [],
            'nameservers': []
        }
        
        try:
            # Check MX records (email servers)
            try:
                mx_records = dns.resolver.resolve(domain, 'MX', lifetime=self.dns_timeout)
                details['mx_records'] = [str(rdata.exchange) for rdata in mx_records]
                details['has_mx'] = True
                results['safe_indicators'].append('Has valid MX records (email configured)')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                results['threat_indicators'].append('No MX records found (no email configured)')
            except Exception as e:
                logger.warning(f"Error checking MX records: {e}")
            
            # Check A records (IP addresses)
            try:
                a_records = dns.resolver.resolve(domain, 'A', lifetime=self.dns_timeout)
                details['a_records'] = [str(rdata) for rdata in a_records]
                details['has_a'] = True
            except Exception as e:
                logger.warning(f"Error checking A records: {e}")
                results['threat_indicators'].append('Unable to resolve domain to IP address')
            
            # Check nameservers
            try:
                ns_records = dns.resolver.resolve(domain, 'NS', lifetime=self.dns_timeout)
                details['nameservers'] = [str(rdata) for rdata in ns_records]
                
                # Check for suspicious nameserver patterns
                ns_string = ' '.join(details['nameservers']).lower()
                if any(pattern in ns_string for pattern in ['parking', 'parked', 'suspended']):
                    results['threat_indicators'].append('Domain may be parked or suspended')
            except Exception as e:
                logger.warning(f"Error checking NS records: {e}")
            
        except Exception as e:
            logger.error(f"Error checking DNS for {domain}: {e}")
            details['error'] = str(e)
        
        results['details']['dns_records'] = details
    
    def _check_blacklists(self, domain: str, results: Dict):
        """Check domain against known blacklists"""
        logger.debug(f"Checking blacklists for: {domain}")
        
        details = {
            'blacklisted': False,
            'sources': []
        }
        
        # Common free blacklist APIs
        blacklist_checks = []
        
        try:
            # Check Google Safe Browsing (requires API key in production)
            # For now, we'll use a simple domain pattern check
            
            # Hardcoded list of known phishing patterns (in production, use API)
            known_bad_patterns = ['phishing', 'scam', 'fake', 'fraud', 'malware', 'virus']
            if any(pattern in domain.lower() for pattern in known_bad_patterns):
                blacklist_checks.append('pattern_match')
                results['threat_indicators'].append('Domain contains known malicious keywords')
                details['blacklisted'] = True
            
            # Check against URLhaus (simplified check)
            # In production, implement actual API call
            
        except Exception as e:
            logger.error(f"Error checking blacklists for {domain}: {e}")
            details['error'] = str(e)
        
        details['sources'] = blacklist_checks
        results['details']['blacklist'] = details
    
    def _check_typosquatting(self, domain: str, results: Dict):
        """Check for typosquatting attempts"""
        logger.debug(f"Checking typosquatting for: {domain}")
        
        # Extract base domain without TLD
        extracted = tldextract.extract(domain)
        base_domain = extracted.domain
        
        typosquat_result = check_typosquatting(base_domain, self.typosquat_targets, threshold=0.75)
        
        if typosquat_result['is_typosquatting']:
            target = typosquat_result['target_domain']
            similarity = typosquat_result['similarity']
            results['threat_indicators'].append(
                f'Possible typosquatting of "{target}" (similarity: {similarity:.2%})'
            )
            typosquat_result['detected'] = True
        else:
            typosquat_result['detected'] = False
        
        results['details']['typosquatting'] = typosquat_result
    
    def _calculate_url_risk(self, results: Dict) -> int:
        """
        Calculate risk score based on URL analysis
        
        Returns:
            Risk score from 0-100
        """
        threat_count = len(results['threat_indicators'])
        safe_count = len(results['safe_indicators'])
        
        # Base calculation
        base_score = min(threat_count * 15, 100)  # Each threat adds 15 points
        base_score = max(base_score - (safe_count * 10), 0)  # Each safe indicator removes 10 points
        
        # Apply weights from config
        weights = self.config.get('url_weights', {})
        
        # Adjust based on specific critical factors
        if results['details'].get('domain_age', {}).get('age_days', 999) < 7:
            base_score += 30  # Very new domain is critical
        
        if results['details'].get('typosquatting', {}).get('detected', False):
            base_score += 25  # Typosquatting is critical
        
        if results['details'].get('blacklist', {}).get('blacklisted', False):
            base_score += 40  # Blacklisted domain is critical
        
        if not results['details'].get('ssl_certificate', {}).get('valid', False):
            base_score += 20  # No SSL is serious
        
        # Cap at 100
        return min(base_score, 100)
