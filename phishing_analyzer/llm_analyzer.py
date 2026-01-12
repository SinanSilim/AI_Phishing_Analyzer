"""
LLM Analyzer Module
Uses OpenAI API for advanced linguistic analysis of phishing attempts
"""

import logging
from typing import Dict, List, Any, Optional
import json

try:
    from openai import OpenAI
except ImportError:
    logging.warning("OpenAI library not available")

logger = logging.getLogger(__name__)


class LLMAnalyzer:
    """Uses Large Language Models to analyze text for phishing indicators"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize LLM Analyzer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.api_key = config.get('openai_api_key', '')
        self.model = config.get('openai_model', 'gpt-4o-mini')
        self.temperature = config.get('openai_temperature', 0.3)
        self.max_tokens = config.get('openai_max_tokens', 500)
        self.enabled = config.get('enable_llm_analysis', True)
        
        if self.api_key and self.api_key != "YOUR_OPENAI_API_KEY_HERE":
            try:
                self.client = OpenAI(api_key=self.api_key)
                self.available = True
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {e}")
                self.available = False
        else:
            logger.warning("OpenAI API key not configured")
            self.available = False
    
    def analyze_text(self, text: str, context: str = "email") -> Dict[str, Any]:
        """
        Analyze text using LLM for phishing indicators
        
        Args:
            text: Text to analyze
            context: Context of the text ('email' or 'url')
            
        Returns:
            Dictionary containing LLM analysis results
        """
        if not self.enabled:
            return {
                'enabled': False,
                'message': 'LLM analysis is disabled'
            }
        
        if not self.available:
            return {
                'enabled': True,
                'available': False,
                'error': 'OpenAI API not available or not configured'
            }
        
        logger.info(f"Performing LLM analysis on {context}")
        
        try:
            # Truncate text if too long
            max_text_length = 4000
            if len(text) > max_text_length:
                text = text[:max_text_length] + "..."
            
            # Create analysis prompt
            prompt = self._create_analysis_prompt(text, context)
            
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in phishing detection. Analyze the provided content for phishing indicators and manipulation tactics."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            
            # Parse response
            analysis_text = response.choices[0].message.content
            
            # Extract structured data from response
            results = self._parse_llm_response(analysis_text)
            results['raw_analysis'] = analysis_text
            results['model_used'] = self.model
            results['available'] = True
            
            return results
            
        except Exception as e:
            logger.error(f"Error in LLM analysis: {e}")
            return {
                'enabled': True,
                'available': True,
                'error': str(e)
            }
    
    def _create_analysis_prompt(self, text: str, context: str) -> str:
        """Create analysis prompt for LLM"""
        
        if context == "email":
            prompt = f"""Analyze the following email text for phishing indicators:

EMAIL TEXT:
{text}

Please provide a detailed analysis covering:
1. Overall Risk Level (Low/Medium/High/Critical)
2. Tone and emotional manipulation tactics
3. Urgency and pressure tactics
4. Threats or consequences mentioned
5. Requests for action or information
6. Linguistic red flags (grammar, style, word choice)
7. Confidence level in your assessment (0-100%)

Provide your analysis in a structured format with clear sections."""
        
        else:  # URL context
            prompt = f"""Analyze the following URL for phishing indicators:

URL: {text}

Please provide a detailed analysis covering:
1. Overall Risk Level (Low/Medium/High/Critical)
2. Domain name analysis (typosquatting, suspicious patterns)
3. URL structure red flags
4. Likelihood of being legitimate
5. Confidence level in your assessment (0-100%)

Provide your analysis in a structured format with clear sections."""
        
        return prompt
    
    def _parse_llm_response(self, response_text: str) -> Dict[str, Any]:
        """
        Parse LLM response into structured data
        
        Args:
            response_text: Raw response from LLM
            
        Returns:
            Dictionary with parsed results
        """
        results = {
            'risk_level': 'Unknown',
            'confidence': 0,
            'tone_analysis': '',
            'manipulation_tactics': [],
            'red_flags': [],
            'summary': ''
        }
        
        try:
            # Extract risk level
            if 'critical' in response_text.lower():
                results['risk_level'] = 'Critical'
            elif 'high' in response_text.lower() and 'risk' in response_text.lower():
                results['risk_level'] = 'High'
            elif 'medium' in response_text.lower():
                results['risk_level'] = 'Medium'
            elif 'low' in response_text.lower():
                results['risk_level'] = 'Low'
            
            # Extract confidence (look for percentage)
            import re
            confidence_match = re.search(r'confidence.*?(\d+)%', response_text.lower())
            if confidence_match:
                results['confidence'] = int(confidence_match.group(1))
            
            # Extract tone analysis (look for "tone" section)
            tone_match = re.search(r'tone.*?:(.*?)(?:\n\n|\d\.)', response_text, re.IGNORECASE | re.DOTALL)
            if tone_match:
                results['tone_analysis'] = tone_match.group(1).strip()
            
            # Extract manipulation tactics
            tactics_keywords = ['urgency', 'fear', 'pressure', 'threat', 'manipulation', 'scarcity']
            found_tactics = []
            for keyword in tactics_keywords:
                if keyword in response_text.lower():
                    found_tactics.append(keyword)
            results['manipulation_tactics'] = found_tactics
            
            # Extract red flags (look for bullet points or numbered lists)
            red_flags = []
            lines = response_text.split('\n')
            for line in lines:
                if any(indicator in line.lower() for indicator in ['red flag', 'suspicious', 'warning', 'concern']):
                    red_flags.append(line.strip())
            results['red_flags'] = red_flags[:10]  # Limit to 10
            
            # Create summary (first few sentences)
            sentences = response_text.split('.')
            results['summary'] = '. '.join(sentences[:2]) + '.' if len(sentences) > 0 else response_text[:200]
            
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
        
        return results
    
    def analyze_tone(self, text: str) -> Dict[str, Any]:
        """
        Focused analysis on tone and emotional manipulation
        
        Args:
            text: Text to analyze
            
        Returns:
            Dictionary with tone analysis
        """
        if not self.available:
            return {'available': False}
        
        try:
            prompt = f"""Analyze the tone and emotional manipulation tactics in the following text:

TEXT:
{text[:2000]}

Focus on:
1. Is the tone aggressive, threatening, or manipulative?
2. What emotions is it trying to evoke (fear, urgency, greed)?
3. Are there psychological pressure tactics?
4. Rate the manipulation level (0-10)

Be concise and direct."""
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a psychology and cybersecurity expert analyzing manipulation tactics."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=self.temperature,
                max_tokens=300
            )
            
            analysis = response.choices[0].message.content
            
            # Extract manipulation score
            import re
            score_match = re.search(r'(\d+)/10', analysis)
            manipulation_score = int(score_match.group(1)) if score_match else 5
            
            return {
                'available': True,
                'analysis': analysis,
                'manipulation_score': manipulation_score,
                'is_aggressive': 'aggressive' in analysis.lower() or 'threatening' in analysis.lower()
            }
            
        except Exception as e:
            logger.error(f"Error in tone analysis: {e}")
            return {
                'available': True,
                'error': str(e)
            }
    
    def get_verdict(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get LLM's final verdict based on all analysis results
        
        Args:
            all_results: Combined results from all analyzers
            
        Returns:
            Dictionary with final verdict
        """
        if not self.available:
            return {'available': False}
        
        try:
            # Summarize findings
            summary = f"""Based on comprehensive analysis:

Risk Score: {all_results.get('risk_score', 0)}/100
Threat Indicators: {len(all_results.get('threat_indicators', []))}
URL Analysis: {all_results.get('url_analysis', {}).get('url_risk_score', 'N/A')}
Email Analysis: {all_results.get('email_analysis', {}).get('email_risk_score', 'N/A')}

Key Findings:
{chr(10).join(['- ' + ti for ti in all_results.get('threat_indicators', [])[:10]])}
"""
            
            prompt = f"""{summary}

Based on the above analysis, provide:
1. Is this definitely phishing? (Yes/No/Likely/Uncertain)
2. Confidence level (0-100%)
3. Primary threat indicators (top 3)
4. Recommended action (Delete/Ignore/Verify/Safe)
5. One-sentence explanation

Be decisive and concise."""
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are making a final determination on whether content is phishing."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,  # Lower temperature for more consistent verdicts
                max_tokens=200
            )
            
            verdict_text = response.choices[0].message.content
            
            # Parse verdict
            is_phishing = any(word in verdict_text.lower() for word in ['yes', 'definitely', 'certainly'])
            
            import re
            confidence_match = re.search(r'(\d+)%', verdict_text)
            confidence = int(confidence_match.group(1)) if confidence_match else 50
            
            return {
                'available': True,
                'is_phishing': is_phishing,
                'confidence': confidence,
                'verdict': verdict_text,
                'recommendation': self._extract_recommendation(verdict_text)
            }
            
        except Exception as e:
            logger.error(f"Error getting LLM verdict: {e}")
            return {
                'available': True,
                'error': str(e)
            }
    
    def _extract_recommendation(self, text: str) -> str:
        """Extract recommendation from verdict text"""
        text_lower = text.lower()
        
        if 'delete' in text_lower or 'block' in text_lower:
            return 'DELETE'
        elif 'ignore' in text_lower:
            return 'IGNORE'
        elif 'verify' in text_lower or 'check' in text_lower:
            return 'VERIFY'
        elif 'safe' in text_lower:
            return 'SAFE'
        else:
            return 'CAUTION'
