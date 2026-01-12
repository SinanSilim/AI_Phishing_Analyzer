"""
Email Analyzer Module
Performs NLP and sentiment analysis on email text to detect phishing attempts
"""

import re
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import Counter

# NLP libraries
try:
    import nltk
    from nltk.tokenize import word_tokenize, sent_tokenize
    from nltk.corpus import stopwords
    from textblob import TextBlob
    from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
except ImportError as e:
    logging.warning(f"Some NLP libraries not available: {e}")

from .utils import extract_urls, extract_emails, sanitize_input

logger = logging.getLogger(__name__)


class EmailAnalyzer:
    """Analyzes email content for phishing indicators"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Email Analyzer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        
        # Load suspicious keywords from config
        self.suspicious_keywords = [kw.lower() for kw in config.get('suspicious_keywords', [])]
        
        # Initialize sentiment analyzer
        self.vader = SentimentIntensityAnalyzer()
        
        # Download required NLTK data
        self._ensure_nltk_data()
        
        # Phishing patterns
        self.urgency_patterns = [
            r'urgent',
            r'immediate(ly)?',
            r'act now',
            r'right away',
            r'within \d+ (hour|day|minute)',
            r'expire[sd]?',
            r'limited time',
            r'last chance',
            r'don\'t wait',
            r'hurry'
        ]
        
        self.threat_patterns = [
            r'suspend(ed)?',
            r'close(d)? (your )?account',
            r'verify (your )?identity',
            r'confirm (your )?account',
            r'unusual activity',
            r'security (alert|breach|issue)',
            r'unauthorized',
            r'locked',
            r'restricted',
            r'compromised'
        ]
        
        self.action_patterns = [
            r'click (here|below|this link)',
            r'download',
            r'open (the )?attachment',
            r'update (your )?information',
            r'verify (your )?account',
            r'confirm (your )?identity',
            r'reset (your )?password',
            r'provide (your )?details'
        ]
        
        self.reward_patterns = [
            r'congratulations',
            r'you\'?ve? won',
            r'prize',
            r'reward',
            r'free',
            r'gift',
            r'claim',
            r'lottery',
            r'million dollar',
            r'inheritance'
        ]
    
    def _ensure_nltk_data(self):
        """Ensure required NLTK data is downloaded"""
        try:
            required_data = ['punkt', 'stopwords', 'averaged_perceptron_tagger']
            for data in required_data:
                try:
                    nltk.data.find(f'tokenizers/{data}')
                except LookupError:
                    logger.info(f"Downloading NLTK data: {data}")
                    nltk.download(data, quiet=True)
        except Exception as e:
            logger.warning(f"Error ensuring NLTK data: {e}")
    
    def analyze(self, email_text: str, email_headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Perform comprehensive email analysis
        
        Args:
            email_text: Email body text
            email_headers: Optional email headers dictionary
            
        Returns:
            Dictionary containing analysis results
        """
        logger.info("Analyzing email content")
        
        # Sanitize input
        email_text = sanitize_input(email_text)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'text_length': len(email_text),
            'checks_performed': [],
            'threat_indicators': [],
            'safe_indicators': [],
            'details': {}
        }
        
        # Perform various analyses
        self._analyze_sentiment(email_text, results)
        results['checks_performed'].append('Sentiment Analysis')
        
        self._check_suspicious_keywords(email_text, results)
        results['checks_performed'].append('Keyword Detection')
        
        self._check_urgency(email_text, results)
        results['checks_performed'].append('Urgency Detection')
        
        self._check_threats(email_text, results)
        results['checks_performed'].append('Threat Detection')
        
        self._check_suspicious_patterns(email_text, results)
        results['checks_performed'].append('Pattern Analysis')
        
        self._analyze_structure(email_text, results)
        results['checks_performed'].append('Structure Analysis')
        
        self._extract_and_check_urls(email_text, results)
        results['checks_performed'].append('URL Extraction')
        
        self._extract_and_check_emails(email_text, results)
        results['checks_performed'].append('Email Extraction')
        
        if email_headers:
            self._analyze_headers(email_headers, results)
            results['checks_performed'].append('Header Analysis')
        
        # Calculate component score
        results['email_risk_score'] = self._calculate_email_risk(results)
        
        return results
    
    def _analyze_sentiment(self, text: str, results: Dict):
        """Analyze sentiment and emotional tone"""
        logger.debug("Analyzing sentiment")
        
        details = {}
        
        try:
            # VADER sentiment analysis
            vader_scores = self.vader.polarity_scores(text)
            details['vader'] = vader_scores
            
            # TextBlob sentiment analysis
            blob = TextBlob(text)
            details['textblob'] = {
                'polarity': blob.sentiment.polarity,
                'subjectivity': blob.sentiment.subjectivity
            }
            
            # Interpret VADER compound score
            compound = vader_scores['compound']
            if compound <= -0.5:
                results['threat_indicators'].append(f'Very negative sentiment detected (score: {compound:.2f})')
            elif compound <= -0.2:
                results['threat_indicators'].append(f'Negative sentiment detected (score: {compound:.2f})')
            elif compound >= 0.5:
                details['tone'] = 'positive'
            
            # Check for extreme emotions
            if vader_scores['neg'] > 0.3:
                results['threat_indicators'].append(f'High negative emotion content ({vader_scores["neg"]:.2%})')
            
            # Check subjectivity (highly subjective can be manipulative)
            if blob.sentiment.subjectivity > 0.7:
                results['threat_indicators'].append('Highly subjective/emotional language')
                details['high_subjectivity'] = True
            
        except Exception as e:
            logger.error(f"Error in sentiment analysis: {e}")
            details['error'] = str(e)
        
        results['details']['sentiment'] = details
    
    def _check_suspicious_keywords(self, text: str, results: Dict):
        """Check for suspicious keywords"""
        logger.debug("Checking suspicious keywords")
        
        text_lower = text.lower()
        found_keywords = []
        
        for keyword in self.suspicious_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        details = {
            'found_keywords': found_keywords,
            'count': len(found_keywords)
        }
        
        if len(found_keywords) > 0:
            results['threat_indicators'].append(
                f'Found {len(found_keywords)} suspicious keywords: {", ".join(found_keywords[:5])}'
            )
        
        if len(found_keywords) > 5:
            results['threat_indicators'].append('Excessive use of suspicious keywords')
        
        results['details']['keywords'] = details
    
    def _check_urgency(self, text: str, results: Dict):
        """Check for urgency and time pressure tactics"""
        logger.debug("Checking urgency indicators")
        
        text_lower = text.lower()
        urgency_matches = []
        
        for pattern in self.urgency_patterns:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                urgency_matches.extend(matches)
        
        details = {
            'urgency_indicators': urgency_matches,
            'count': len(urgency_matches)
        }
        
        if len(urgency_matches) > 0:
            results['threat_indicators'].append(
                f'Contains urgency/time pressure tactics ({len(urgency_matches)} instances)'
            )
        
        if len(urgency_matches) > 3:
            results['threat_indicators'].append('Excessive urgency language (red flag)')
        
        # Check for ALL CAPS (shouting)
        caps_words = [word for word in text.split() if word.isupper() and len(word) > 2]
        if len(caps_words) > 3:
            results['threat_indicators'].append(f'Excessive use of ALL CAPS ({len(caps_words)} words)')
            details['caps_words'] = caps_words[:10]
        
        # Check for excessive exclamation marks
        exclamation_count = text.count('!')
        if exclamation_count > 3:
            results['threat_indicators'].append(f'Excessive exclamation marks ({exclamation_count})')
            details['exclamation_count'] = exclamation_count
        
        results['details']['urgency'] = details
    
    def _check_threats(self, text: str, results: Dict):
        """Check for threatening language"""
        logger.debug("Checking threat patterns")
        
        text_lower = text.lower()
        threat_matches = []
        
        for pattern in self.threat_patterns:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                threat_matches.extend(matches)
        
        details = {
            'threat_indicators': threat_matches,
            'count': len(threat_matches)
        }
        
        if len(threat_matches) > 0:
            results['threat_indicators'].append(
                f'Contains threatening language ({len(threat_matches)} instances)'
            )
        
        if len(threat_matches) > 2:
            results['threat_indicators'].append('Multiple threats detected (serious red flag)')
        
        results['details']['threats'] = details
    
    def _check_suspicious_patterns(self, text: str, results: Dict):
        """Check for various suspicious patterns"""
        logger.debug("Checking suspicious patterns")
        
        details = {}
        
        # Check for action requests
        text_lower = text.lower()
        action_matches = []
        
        for pattern in self.action_patterns:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                action_matches.extend(matches)
        
        if action_matches:
            results['threat_indicators'].append(
                f'Requests suspicious actions ({len(action_matches)} requests)'
            )
            details['action_requests'] = action_matches
        
        # Check for reward/prize patterns (common in scams)
        reward_matches = []
        for pattern in self.reward_patterns:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                reward_matches.extend(matches)
        
        if reward_matches:
            results['threat_indicators'].append(
                f'Contains reward/prize language (common scam tactic)'
            )
            details['reward_language'] = reward_matches
        
        # Check for money requests
        money_patterns = [r'\$\d+', r'\d+\s*dollar', r'\d+\s*USD', r'send money', r'wire transfer', r'bank account']
        money_matches = []
        for pattern in money_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                money_matches.extend(matches)
        
        if money_matches:
            results['threat_indicators'].append('References money or payments')
            details['money_references'] = money_matches
        
        # Check for personal information requests
        personal_info_patterns = [
            r'social security',
            r'ssn',
            r'credit card',
            r'bank account',
            r'password',
            r'pin\s*code',
            r'date of birth',
            r'driver\'?s? license'
        ]
        
        pii_matches = []
        for pattern in personal_info_patterns:
            if re.search(pattern, text_lower):
                pii_matches.append(pattern)
        
        if pii_matches:
            results['threat_indicators'].append(
                f'Requests personal/sensitive information: {", ".join(pii_matches)}'
            )
            details['pii_requests'] = pii_matches
        
        # Check for poor grammar (common in phishing)
        sentences = sent_tokenize(text)
        if len(sentences) > 2:
            blob = TextBlob(text)
            # This is a simplified check - in production use better grammar checking
            details['sentences_count'] = len(sentences)
        
        results['details']['patterns'] = details
    
    def _analyze_structure(self, text: str, results: Dict):
        """Analyze email structure and composition"""
        logger.debug("Analyzing structure")
        
        details = {
            'char_count': len(text),
            'word_count': len(text.split()),
            'sentence_count': len(sent_tokenize(text))
        }
        
        # Check for very short emails with links (suspicious)
        if details['word_count'] < 20 and len(extract_urls(text)) > 0:
            results['threat_indicators'].append('Very short message with links (suspicious)')
            details['short_with_links'] = True
        
        # Check for very long emails (sometimes used to hide phishing content)
        if details['word_count'] > 1000:
            results['threat_indicators'].append('Unusually long email')
            details['unusually_long'] = True
        
        # Check sentence structure
        if details['sentence_count'] > 0:
            avg_words_per_sentence = details['word_count'] / details['sentence_count']
            details['avg_words_per_sentence'] = avg_words_per_sentence
            
            if avg_words_per_sentence > 40:
                results['threat_indicators'].append('Very long sentences (may indicate poor composition)')
        
        # Check for greeting/signature
        has_greeting = bool(re.search(r'^(dear|hello|hi|greetings)', text.lower().strip()))
        has_signature = bool(re.search(r'(sincerely|regards|best|thanks)', text.lower()[-200:]))
        
        details['has_greeting'] = has_greeting
        details['has_signature'] = has_signature
        
        if not has_greeting and not has_signature:
            results['threat_indicators'].append('Missing typical email greeting and signature')
        
        results['details']['structure'] = details
    
    def _extract_and_check_urls(self, text: str, results: Dict):
        """Extract and analyze URLs from email"""
        logger.debug("Extracting URLs")
        
        urls = extract_urls(text)
        
        details = {
            'url_count': len(urls),
            'urls': urls[:10]  # Store first 10 URLs
        }
        
        if len(urls) > 5:
            results['threat_indicators'].append(f'Contains many links ({len(urls)} URLs)')
        elif len(urls) == 0:
            results['safe_indicators'].append('No embedded links')
        
        # Check for suspicious URL patterns
        suspicious_url_indicators = []
        for url in urls:
            url_lower = url.lower()
            if any(pattern in url_lower for pattern in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']):
                suspicious_url_indicators.append('URL shortener')
            if url_lower.startswith('http://'):
                suspicious_url_indicators.append('Non-HTTPS link')
            if '@' in url:
                suspicious_url_indicators.append('URL with @ symbol')
            if len(url) > 100:
                suspicious_url_indicators.append('Very long URL')
        
        if suspicious_url_indicators:
            results['threat_indicators'].append(
                f'Suspicious URL characteristics: {", ".join(set(suspicious_url_indicators))}'
            )
            details['suspicious_indicators'] = list(set(suspicious_url_indicators))
        
        results['details']['urls'] = details
    
    def _extract_and_check_emails(self, text: str, results: Dict):
        """Extract and analyze email addresses"""
        logger.debug("Extracting email addresses")
        
        emails = extract_emails(text)
        
        details = {
            'email_count': len(emails),
            'emails': emails
        }
        
        # Check for suspicious email domains
        suspicious_domains = []
        for email in emails:
            domain = email.split('@')[1] if '@' in email else ''
            if domain and any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']):
                suspicious_domains.append(domain)
        
        if suspicious_domains:
            results['threat_indicators'].append(f'Suspicious email domains: {", ".join(suspicious_domains)}')
            details['suspicious_domains'] = suspicious_domains
        
        results['details']['email_addresses'] = details
    
    def _analyze_headers(self, headers: Dict, results: Dict):
        """Analyze email headers for spoofing indicators"""
        logger.debug("Analyzing email headers")
        
        details = {
            'from': headers.get('from', ''),
            'reply_to': headers.get('reply-to', ''),
            'return_path': headers.get('return-path', '')
        }
        
        # Check if from and reply-to don't match
        if details['from'] and details['reply_to']:
            from_domain = details['from'].split('@')[1] if '@' in details['from'] else ''
            reply_domain = details['reply_to'].split('@')[1] if '@' in details['reply_to'] else ''
            
            if from_domain and reply_domain and from_domain != reply_domain:
                results['threat_indicators'].append(
                    'From and Reply-To addresses have different domains (possible spoofing)'
                )
                details['domain_mismatch'] = True
        
        # Check for display name spoofing
        from_field = headers.get('from', '')
        if '<' in from_field and '>' in from_field:
            display_name = from_field.split('<')[0].strip()
            email_addr = from_field.split('<')[1].split('>')[0]
            
            # Check if display name contains a different domain
            if '@' in display_name or '.com' in display_name.lower():
                results['threat_indicators'].append('Display name spoofing detected')
                details['display_name_spoofing'] = True
        
        results['details']['headers'] = details
    
    def _calculate_email_risk(self, results: Dict) -> int:
        """
        Calculate risk score based on email analysis
        
        Returns:
            Risk score from 0-100
        """
        threat_count = len(results['threat_indicators'])
        safe_count = len(results['safe_indicators'])
        
        # Base calculation
        base_score = min(threat_count * 12, 100)
        base_score = max(base_score - (safe_count * 8), 0)
        
        # Apply weights based on severity
        details = results['details']
        
        # High severity indicators
        if details.get('threats', {}).get('count', 0) > 2:
            base_score += 25
        
        if details.get('patterns', {}).get('pii_requests'):
            base_score += 20
        
        if details.get('urgency', {}).get('count', 0) > 3:
            base_score += 15
        
        if details.get('sentiment', {}).get('vader', {}).get('compound', 0) < -0.5:
            base_score += 10
        
        # Cap at 100
        return min(base_score, 100)
