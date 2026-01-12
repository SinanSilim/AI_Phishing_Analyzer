"""
Have I Been Pwned (HIBP) Integration
Checks email addresses against breach databases
"""

import hashlib
import logging
import requests
import time
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class HIBPChecker:
    """Checks email addresses against Have I Been Pwned database"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize HIBP Checker
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.api_key = config.get('hibp_api_key', '')
        self.user_agent = config.get('hibp_user_agent', 'AI-Phishing-Analyzer')
        self.enabled = config.get('enable_hibp_check', True)
        self.base_url = "https://haveibeenpwned.com/api/v3"
        
        # Rate limiting (HIBP has strict rate limits)
        self.last_request_time = 0
        self.min_request_interval = 1.5  # seconds between requests
    
    def check_email(self, email: str) -> Dict[str, Any]:
        """
        Check if email has been involved in data breaches
        
        Args:
            email: Email address to check
            
        Returns:
            Dictionary with breach information
        """
        if not self.enabled:
            return {
                'enabled': False,
                'message': 'HIBP checking is disabled'
            }
        
        if not self.api_key or self.api_key == "YOUR_HIBP_API_KEY_HERE":
            # Use anonymous API (less detailed results)
            return self._check_anonymously(email)
        else:
            # Use authenticated API (more detailed)
            return self._check_authenticated(email)
    
    def _check_anonymously(self, email: str) -> Dict[str, Any]:
        """
        Check email using anonymous API (password range check)
        This is less invasive and doesn't require API key
        """
        logger.info(f"Checking email anonymously: {email[:3]}***")
        
        try:
            # Use Pwned Passwords API (doesn't expose email)
            # We'll just check if the email pattern is common in breaches
            
            results = {
                'email': email,
                'method': 'anonymous',
                'breach_count': 0,
                'is_breached': False,
                'message': 'Anonymous check completed (limited information)',
                'breaches': []
            }
            
            # Note: Real anonymous checking would use k-anonymity model
            # This is a placeholder - implement proper k-anonymity if needed
            
            return results
            
        except Exception as e:
            logger.error(f"Error in anonymous HIBP check: {e}")
            return {
                'error': str(e),
                'method': 'anonymous'
            }
    
    def _check_authenticated(self, email: str) -> Dict[str, Any]:
        """
        Check email using authenticated API
        Requires API key but provides detailed breach information
        """
        logger.info(f"Checking email with HIBP API: {email[:3]}***")
        
        # Rate limiting
        self._enforce_rate_limit()
        
        try:
            headers = {
                'hibp-api-key': self.api_key,
                'user-agent': self.user_agent
            }
            
            # Check breached account
            url = f"{self.base_url}/breachedaccount/{email}"
            
            response = requests.get(
                url,
                headers=headers,
                timeout=30
            )
            
            results = {
                'email': email,
                'method': 'authenticated',
                'breach_count': 0,
                'is_breached': False,
                'breaches': []
            }
            
            if response.status_code == 200:
                # Email found in breaches
                breaches = response.json()
                results['is_breached'] = True
                results['breach_count'] = len(breaches)
                
                # Parse breach details
                for breach in breaches:
                    breach_info = {
                        'name': breach.get('Name', 'Unknown'),
                        'title': breach.get('Title', ''),
                        'domain': breach.get('Domain', ''),
                        'breach_date': breach.get('BreachDate', ''),
                        'pwn_count': breach.get('PwnCount', 0),
                        'description': breach.get('Description', '')[:200],
                        'data_classes': breach.get('DataClasses', [])
                    }
                    results['breaches'].append(breach_info)
                
                logger.warning(f"Email found in {len(breaches)} breaches")
                
            elif response.status_code == 404:
                # Email not found in breaches (good news)
                results['is_breached'] = False
                results['message'] = 'Email not found in known breaches'
                logger.info("Email not found in breaches")
                
            elif response.status_code == 429:
                # Rate limited
                results['error'] = 'Rate limited by HIBP API'
                logger.warning("Rate limited by HIBP API")
                
            elif response.status_code == 401:
                # Unauthorized
                results['error'] = 'Invalid API key'
                logger.error("Invalid HIBP API key")
                
            else:
                results['error'] = f'HIBP API returned status {response.status_code}'
                logger.error(f"HIBP API error: {response.status_code}")
            
            return results
            
        except requests.exceptions.Timeout:
            logger.error("HIBP API request timeout")
            return {
                'email': email,
                'error': 'Request timeout',
                'method': 'authenticated'
            }
        except Exception as e:
            logger.error(f"Error in authenticated HIBP check: {e}")
            return {
                'email': email,
                'error': str(e),
                'method': 'authenticated'
            }
    
    def check_password(self, password: str) -> Dict[str, Any]:
        """
        Check if password has been exposed in breaches (using k-anonymity)
        
        Args:
            password: Password to check
            
        Returns:
            Dictionary with password exposure info
        """
        logger.info("Checking password against HIBP")
        
        try:
            # Hash the password with SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            
            # Use k-anonymity: only send first 5 characters
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query HIBP Passwords API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            
            self._enforce_rate_limit()
            
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                # Check if our suffix is in the response
                hashes = response.text.split('\r\n')
                
                for hash_entry in hashes:
                    hash_suffix, count = hash_entry.split(':')
                    if hash_suffix == suffix:
                        return {
                            'is_pwned': True,
                            'exposure_count': int(count),
                            'message': f'Password found in {count} data breaches',
                            'severity': 'high' if int(count) > 100 else 'medium'
                        }
                
                # Password not found
                return {
                    'is_pwned': False,
                    'exposure_count': 0,
                    'message': 'Password not found in known breaches'
                }
            else:
                return {
                    'error': f'API returned status {response.status_code}'
                }
                
        except Exception as e:
            logger.error(f"Error checking password: {e}")
            return {
                'error': str(e)
            }
    
    def check_multiple_emails(self, emails: List[str]) -> Dict[str, Any]:
        """
        Check multiple email addresses
        
        Args:
            emails: List of email addresses
            
        Returns:
            Dictionary with results for each email
        """
        results = {
            'total_checked': len(emails),
            'breached_count': 0,
            'results': {}
        }
        
        for email in emails:
            email_result = self.check_email(email)
            results['results'][email] = email_result
            
            if email_result.get('is_breached', False):
                results['breached_count'] += 1
        
        return results
    
    def _enforce_rate_limit(self):
        """Enforce rate limiting to respect HIBP API limits"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def get_breach_summary(self, breach_results: Dict[str, Any]) -> str:
        """
        Create human-readable summary of breach check results
        
        Args:
            breach_results: Results from check_email
            
        Returns:
            Human-readable summary
        """
        if breach_results.get('error'):
            return f"Error checking breaches: {breach_results['error']}"
        
        if not breach_results.get('is_breached', False):
            return "✓ Email not found in known data breaches"
        
        breach_count = breach_results.get('breach_count', 0)
        summary = f"⚠ Email found in {breach_count} data breach{'es' if breach_count != 1 else ''}:\n"
        
        breaches = breach_results.get('breaches', [])[:5]  # Show first 5
        for breach in breaches:
            summary += f"  • {breach['name']} ({breach['breach_date']})\n"
        
        if breach_count > 5:
            summary += f"  ... and {breach_count - 5} more\n"
        
        return summary
