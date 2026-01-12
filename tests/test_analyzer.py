"""
Unit tests for PhishingAnalyzer
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from phishing_analyzer import PhishingAnalyzer
from phishing_analyzer.utils import (
    extract_domain,
    extract_urls,
    extract_emails,
    check_typosquatting,
    calculate_entropy
)


class TestUtils(unittest.TestCase):
    """Test utility functions"""
    
    def test_extract_domain(self):
        """Test domain extraction"""
        self.assertEqual(extract_domain("https://www.google.com/search"), "www.google.com")
        self.assertEqual(extract_domain("http://example.com"), "example.com")
        self.assertEqual(extract_domain("google.com"), "google.com")
    
    def test_extract_urls(self):
        """Test URL extraction from text"""
        text = "Visit https://example.com or http://test.org for more info"
        urls = extract_urls(text)
        self.assertEqual(len(urls), 2)
        self.assertIn("https://example.com", urls)
    
    def test_extract_emails(self):
        """Test email extraction"""
        text = "Contact us at support@example.com or sales@test.org"
        emails = extract_emails(text)
        self.assertEqual(len(emails), 2)
        self.assertIn("support@example.com", emails)
    
    def test_typosquatting_detection(self):
        """Test typosquatting detection"""
        result = check_typosquatting("paypa1", ["paypal"], threshold=0.7)
        self.assertTrue(result['is_typosquatting'])
        self.assertEqual(result['target_domain'], "paypal")
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        # Random string should have high entropy
        high_entropy = calculate_entropy("xkcd9384jdks")
        # Simple pattern should have lower entropy
        low_entropy = calculate_entropy("aaabbbccc")
        self.assertGreater(high_entropy, low_entropy)


class TestAnalyzer(unittest.TestCase):
    """Test main analyzer"""
    
    @classmethod
    def setUpClass(cls):
        """Initialize analyzer once for all tests"""
        cls.analyzer = PhishingAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly"""
        self.assertIsNotNone(self.analyzer)
        self.assertIsNotNone(self.analyzer.url_analyzer)
        self.assertIsNotNone(self.analyzer.email_analyzer)
    
    def test_safe_url_analysis(self):
        """Test analysis of known safe URL"""
        results = self.analyzer.analyze_url("https://www.google.com", use_llm=False)
        self.assertIsNotNone(results)
        self.assertIn('risk_score', results)
        self.assertIn('risk_level', results)
        # Google should have a low risk score
        self.assertLess(results['risk_score'], 50)
    
    def test_suspicious_url_analysis(self):
        """Test analysis of suspicious URL"""
        # Typosquatting example
        results = self.analyzer.analyze_url("http://paypa1-secure.tk", use_llm=False)
        self.assertIsNotNone(results)
        # Should have high risk score
        self.assertGreater(results['risk_score'], 50)
    
    def test_phishing_email_analysis(self):
        """Test analysis of phishing email"""
        phishing_text = """
        URGENT! Your account has been suspended!
        Click here immediately to verify your account or it will be deleted within 24 hours!
        http://verify-account-now.tk
        """
        results = self.analyzer.analyze_email(phishing_text, use_llm=False, check_hibp=False)
        self.assertIsNotNone(results)
        # Should detect urgency and threats
        self.assertGreater(results['risk_score'], 40)
        self.assertGreater(len(results['threat_indicators']), 0)
    
    def test_legitimate_email_analysis(self):
        """Test analysis of legitimate email"""
        legitimate_text = """
        Thank you for your order.
        Your package will arrive in 3-5 business days.
        Order number: 12345
        """
        results = self.analyzer.analyze_email(legitimate_text, use_llm=False, check_hibp=False)
        self.assertIsNotNone(results)
        # Should have lower risk score
        self.assertLess(results['risk_score'], 60)


def run_tests():
    """Run all tests"""
    unittest.main()


if __name__ == '__main__':
    run_tests()
