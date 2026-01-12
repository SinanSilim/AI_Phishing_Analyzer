"""
Main Phishing Analyzer
Coordinates all analysis modules and provides unified interface
"""

import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from .url_analyzer import URLAnalyzer
from .email_analyzer import EmailAnalyzer
from .llm_analyzer import LLMAnalyzer
from .hibp_checker import HIBPChecker
from .risk_scorer import RiskScorer
from .utils import extract_urls, extract_emails, sanitize_input

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PhishingAnalyzer:
    """
    Main phishing analyzer class that coordinates all analysis modules
    """
    
    def __init__(self, config_path: str = 'config.yaml'):
        """
        Initialize Phishing Analyzer
        
        Args:
            config_path: Path to configuration file
        """
        logger.info("Initializing Phishing Analyzer")
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize all analysis modules
        self.url_analyzer = URLAnalyzer(self.config)
        self.email_analyzer = EmailAnalyzer(self.config)
        self.llm_analyzer = LLMAnalyzer(self.config)
        self.hibp_checker = HIBPChecker(self.config)
        self.risk_scorer = RiskScorer(self.config)
        
        logger.info("Phishing Analyzer initialized successfully")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        
        try:
            config_file = Path(config_path)
            
            if not config_file.exists():
                logger.warning(f"Config file not found: {config_path}")
                logger.info("Using default configuration")
                return self._get_default_config()
            
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            logger.info(f"Configuration loaded from {config_path}")
            return config
            
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            logger.info("Using default configuration")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'openai_api_key': '',
            'openai_model': 'gpt-4o-mini',
            'hibp_api_key': '',
            'enable_llm_analysis': False,
            'enable_hibp_check': False,
            'enable_ssl_check': True,
            'enable_whois_check': True,
            'enable_dns_check': True,
            'risk_thresholds': {'low': 25, 'medium': 50, 'high': 75},
            'suspicious_keywords': [
                'urgent', 'verify', 'suspended', 'confirm', 'expire',
                'immediate action', 'security alert', 'unusual activity'
            ],
            'suspicious_tlds': ['.tk', '.ml', '.ga', '.cf', '.gq'],
            'typosquat_targets': [
                'paypal', 'google', 'amazon', 'microsoft', 'apple',
                'facebook', 'instagram', 'bank'
            ],
            'trusted_domains': ['google.com', 'microsoft.com', 'apple.com'],
            'domain_age': {'very_new': 7, 'new': 30, 'established': 180},
            'ssl_check_timeout': 10,
            'whois_timeout': 15,
            'dns_timeout': 10
        }
    
    def analyze_url(self, url: str, use_llm: bool = True) -> Dict[str, Any]:
        """
        Analyze a URL for phishing indicators
        
        Args:
            url: URL to analyze
            use_llm: Whether to use LLM analysis
            
        Returns:
            Dictionary with complete analysis results
        """
        logger.info(f"Starting URL analysis: {url}")
        
        url = sanitize_input(url)
        
        results = {
            'analysis_type': 'url',
            'input': url,
            'url_analysis': None,
            'llm_analysis': None,
            'overall_risk': None
        }
        
        try:
            # URL analysis
            url_results = self.url_analyzer.analyze(url)
            results['url_analysis'] = url_results
            
            # LLM analysis
            if use_llm and self.config.get('enable_llm_analysis'):
                llm_results = self.llm_analyzer.analyze_text(url, context='url')
                results['llm_analysis'] = llm_results
            
            # Calculate overall risk
            overall_risk = self.risk_scorer.calculate_overall_risk(
                url_analysis=url_results,
                llm_analysis=results.get('llm_analysis')
            )
            results['overall_risk'] = overall_risk
            
            # Add convenience fields
            results['risk_score'] = overall_risk['risk_score']
            results['risk_level'] = overall_risk['risk_level']
            results['threat_indicators'] = overall_risk['threat_indicators']
            results['recommendations'] = overall_risk['recommendations']
            
            logger.info(f"URL analysis complete. Risk score: {results['risk_score']}")
            
        except Exception as e:
            logger.error(f"Error in URL analysis: {e}")
            results['error'] = str(e)
            results['risk_score'] = 100
            results['risk_level'] = 'ERROR'
        
        return results
    
    def analyze_email(
        self,
        email_text: str,
        email_headers: Optional[Dict] = None,
        use_llm: bool = True,
        check_hibp: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze email content for phishing indicators
        
        Args:
            email_text: Email body text
            email_headers: Optional email headers
            use_llm: Whether to use LLM analysis
            check_hibp: Whether to check emails against HIBP
            
        Returns:
            Dictionary with complete analysis results
        """
        logger.info("Starting email analysis")
        
        email_text = sanitize_input(email_text)
        
        results = {
            'analysis_type': 'email',
            'input_length': len(email_text),
            'email_analysis': None,
            'url_analysis': None,
            'llm_analysis': None,
            'hibp_results': None,
            'overall_risk': None
        }
        
        try:
            # Email text analysis
            email_results = self.email_analyzer.analyze(email_text, email_headers)
            results['email_analysis'] = email_results
            
            # Extract and analyze URLs from email
            urls = extract_urls(email_text)
            if urls:
                logger.info(f"Found {len(urls)} URLs in email, analyzing first one")
                # Analyze the first URL (most likely to be the phishing link)
                url_results = self.url_analyzer.analyze(urls[0])
                results['url_analysis'] = url_results
                results['extracted_urls'] = urls
            
            # LLM analysis
            if use_llm and self.config.get('enable_llm_analysis'):
                llm_results = self.llm_analyzer.analyze_text(email_text, context='email')
                results['llm_analysis'] = llm_results
                
                # Get tone analysis
                tone_results = self.llm_analyzer.analyze_tone(email_text)
                if tone_results.get('available'):
                    results['tone_analysis'] = tone_results
            
            # HIBP check for email addresses
            if check_hibp and self.config.get('enable_hibp_check'):
                emails = extract_emails(email_text)
                if emails:
                    logger.info(f"Checking {len(emails)} email addresses against HIBP")
                    hibp_results = self.hibp_checker.check_email(emails[0])
                    results['hibp_results'] = hibp_results
                    results['extracted_emails'] = emails
            
            # Calculate overall risk
            overall_risk = self.risk_scorer.calculate_overall_risk(
                url_analysis=results.get('url_analysis'),
                email_analysis=email_results,
                llm_analysis=results.get('llm_analysis'),
                hibp_results=results.get('hibp_results')
            )
            results['overall_risk'] = overall_risk
            
            # Add convenience fields
            results['risk_score'] = overall_risk['risk_score']
            results['risk_level'] = overall_risk['risk_level']
            results['threat_indicators'] = overall_risk['threat_indicators']
            results['recommendations'] = overall_risk['recommendations']
            
            logger.info(f"Email analysis complete. Risk score: {results['risk_score']}")
            
        except Exception as e:
            logger.error(f"Error in email analysis: {e}")
            results['error'] = str(e)
            results['risk_score'] = 100
            results['risk_level'] = 'ERROR'
        
        return results
    
    def analyze_mixed(
        self,
        text: str,
        use_llm: bool = True,
        check_hibp: bool = True
    ) -> Dict[str, Any]:
        """
        Automatically detect and analyze URLs or email content
        
        Args:
            text: Text that may contain URL or email content
            use_llm: Whether to use LLM analysis
            check_hibp: Whether to check against HIBP
            
        Returns:
            Dictionary with complete analysis results
        """
        logger.info("Starting mixed analysis (auto-detect)")
        
        text = sanitize_input(text)
        
        # Try to detect if input is a URL
        if text.startswith(('http://', 'https://')) or '.' in text.split()[0]:
            # Looks like a URL
            logger.info("Input detected as URL")
            return self.analyze_url(text, use_llm=use_llm)
        else:
            # Treat as email content
            logger.info("Input detected as email text")
            return self.analyze_email(text, use_llm=use_llm, check_hibp=check_hibp)
    
    def get_summary(self, results: Dict[str, Any]) -> str:
        """
        Get human-readable summary of analysis results
        
        Args:
            results: Analysis results dictionary
            
        Returns:
            Formatted summary string
        """
        return self.risk_scorer.get_risk_summary(results.get('overall_risk', results))
    
    def batch_analyze_urls(self, urls: list, use_llm: bool = False) -> Dict[str, Any]:
        """
        Analyze multiple URLs in batch
        
        Args:
            urls: List of URLs to analyze
            use_llm: Whether to use LLM (disabled by default for batch)
            
        Returns:
            Dictionary with results for each URL
        """
        logger.info(f"Starting batch analysis of {len(urls)} URLs")
        
        results = {
            'total_urls': len(urls),
            'completed': 0,
            'failed': 0,
            'results': {}
        }
        
        for i, url in enumerate(urls, 1):
            try:
                logger.info(f"Analyzing URL {i}/{len(urls)}")
                url_result = self.analyze_url(url, use_llm=use_llm)
                results['results'][url] = url_result
                results['completed'] += 1
            except Exception as e:
                logger.error(f"Failed to analyze {url}: {e}")
                results['results'][url] = {'error': str(e)}
                results['failed'] += 1
        
        logger.info(f"Batch analysis complete. {results['completed']}/{len(urls)} successful")
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics and status of the analyzer
        
        Returns:
            Dictionary with analyzer statistics
        """
        return {
            'version': '1.0.0',
            'llm_available': self.llm_analyzer.available if hasattr(self.llm_analyzer, 'available') else False,
            'llm_enabled': self.config.get('enable_llm_analysis', False),
            'hibp_enabled': self.config.get('enable_hibp_check', False),
            'ssl_check_enabled': self.config.get('enable_ssl_check', True),
            'whois_check_enabled': self.config.get('enable_whois_check', True),
            'dns_check_enabled': self.config.get('enable_dns_check', True),
            'model': self.config.get('openai_model', 'N/A')
        }


def quick_analyze(input_text: str, config_path: str = 'config.yaml') -> Dict[str, Any]:
    """
    Quick analysis function for simple use cases
    
    Args:
        input_text: URL or email text to analyze
        config_path: Path to config file
        
    Returns:
        Analysis results
    """
    analyzer = PhishingAnalyzer(config_path)
    return analyzer.analyze_mixed(input_text)
