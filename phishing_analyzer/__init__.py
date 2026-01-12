"""
AI-Powered Phishing Analyzer
A comprehensive tool for detecting phishing attempts in URLs and emails
"""

from .analyzer import PhishingAnalyzer
from .url_analyzer import URLAnalyzer
from .email_analyzer import EmailAnalyzer
from .risk_scorer import RiskScorer

__version__ = "1.0.0"
__author__ = "AI Phishing Analyzer Team"
__all__ = ["PhishingAnalyzer", "URLAnalyzer", "EmailAnalyzer", "RiskScorer"]
