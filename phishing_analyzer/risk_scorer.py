"""
Risk Scoring Engine
Combines all analysis results to calculate overall risk score
"""

import logging
from typing import Dict, List, Any
from datetime import datetime

from .utils import format_risk_level

logger = logging.getLogger(__name__)


class RiskScorer:
    """Calculates overall risk scores from multiple analysis components"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Risk Scorer
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        
        # Load weights from config
        self.url_weights = config.get('url_weights', {
            'domain_age': 0.25,
            'ssl_certificate': 0.20,
            'dns_check': 0.15,
            'blacklist': 0.25,
            'url_pattern': 0.15
        })
        
        self.email_weights = config.get('email_weights', {
            'sentiment': 0.20,
            'keywords': 0.20,
            'urgency': 0.15,
            'llm_analysis': 0.30,
            'structure': 0.15
        })
        
        self.risk_thresholds = config.get('risk_thresholds', {
            'low': 25,
            'medium': 50,
            'high': 75
        })
    
    def calculate_overall_risk(
        self,
        url_analysis: Dict[str, Any] = None,
        email_analysis: Dict[str, Any] = None,
        llm_analysis: Dict[str, Any] = None,
        hibp_results: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Calculate overall risk score from all analysis components
        
        Args:
            url_analysis: Results from URLAnalyzer
            email_analysis: Results from EmailAnalyzer
            llm_analysis: Results from LLMAnalyzer
            hibp_results: Results from HIBPChecker
            
        Returns:
            Dictionary with overall risk assessment
        """
        logger.info("Calculating overall risk score")
        
        component_scores = {}
        total_weight = 0.0
        weighted_sum = 0.0
        
        # URL component (30% of total if available)
        if url_analysis and not url_analysis.get('error'):
            url_score = url_analysis.get('url_risk_score', 0)
            url_weight = 0.30
            component_scores['url'] = url_score
            weighted_sum += url_score * url_weight
            total_weight += url_weight
        
        # Email component (30% of total if available)
        if email_analysis and not email_analysis.get('error'):
            email_score = email_analysis.get('email_risk_score', 0)
            email_weight = 0.30
            component_scores['email'] = email_score
            weighted_sum += email_score * email_weight
            total_weight += email_weight
        
        # LLM component (25% of total if available)
        if llm_analysis and llm_analysis.get('available'):
            llm_score = self._calculate_llm_score(llm_analysis)
            llm_weight = 0.25
            component_scores['llm'] = llm_score
            weighted_sum += llm_score * llm_weight
            total_weight += llm_weight
        
        # HIBP component (15% of total if available)
        if hibp_results and hibp_results.get('is_breached'):
            hibp_score = self._calculate_hibp_score(hibp_results)
            hibp_weight = 0.15
            component_scores['hibp'] = hibp_score
            weighted_sum += hibp_score * hibp_weight
            total_weight += hibp_weight
        
        # Calculate final score
        if total_weight > 0:
            final_score = int(weighted_sum / total_weight)
        else:
            final_score = 0
        
        # Ensure score is in valid range
        final_score = max(0, min(100, final_score))
        
        # Determine risk level
        risk_level = self._determine_risk_level(final_score)
        
        # Compile threat indicators
        all_threat_indicators = []
        if url_analysis:
            all_threat_indicators.extend(url_analysis.get('threat_indicators', []))
        if email_analysis:
            all_threat_indicators.extend(email_analysis.get('threat_indicators', []))
        if llm_analysis and llm_analysis.get('red_flags'):
            all_threat_indicators.extend(llm_analysis.get('red_flags', []))
        
        # Compile safe indicators
        all_safe_indicators = []
        if url_analysis:
            all_safe_indicators.extend(url_analysis.get('safe_indicators', []))
        if email_analysis:
            all_safe_indicators.extend(email_analysis.get('safe_indicators', []))
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            final_score,
            risk_level,
            component_scores,
            all_threat_indicators
        )
        
        return {
            'risk_score': final_score,
            'risk_level': risk_level,
            'component_scores': component_scores,
            'threat_indicators': all_threat_indicators,
            'safe_indicators': all_safe_indicators,
            'recommendations': recommendations,
            'confidence': self._calculate_confidence(component_scores),
            'timestamp': datetime.now().isoformat()
        }
    
    def _calculate_llm_score(self, llm_analysis: Dict[str, Any]) -> int:
        """Calculate score from LLM analysis"""
        
        # Map risk level to score
        risk_level = llm_analysis.get('risk_level', 'Unknown').lower()
        risk_map = {
            'critical': 90,
            'high': 70,
            'medium': 45,
            'low': 20,
            'unknown': 50
        }
        
        base_score = risk_map.get(risk_level, 50)
        
        # Adjust based on manipulation score if available
        manipulation_score = llm_analysis.get('manipulation_score', 0)
        if manipulation_score > 0:
            # Manipulation score is 0-10, scale it
            base_score += (manipulation_score * 2)
        
        # Adjust based on confidence
        confidence = llm_analysis.get('confidence', 50)
        if confidence < 50:
            # Lower confidence means we should be more cautious
            base_score = base_score * 0.8
        
        return min(100, int(base_score))
    
    def _calculate_hibp_score(self, hibp_results: Dict[str, Any]) -> int:
        """Calculate score from HIBP results"""
        
        if not hibp_results.get('is_breached', False):
            return 0
        
        breach_count = hibp_results.get('breach_count', 0)
        
        # Each breach adds risk
        # 1 breach = 30 points, 2 = 50, 3+ = 70
        if breach_count == 1:
            return 30
        elif breach_count == 2:
            return 50
        elif breach_count >= 3:
            return 70
        
        return 0
    
    def _determine_risk_level(self, score: int) -> str:
        """Determine risk level category from score"""
        
        thresholds = self.risk_thresholds
        
        if score <= thresholds['low']:
            return 'LOW'
        elif score <= thresholds['medium']:
            return 'MEDIUM'
        elif score <= thresholds['high']:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def _calculate_confidence(self, component_scores: Dict[str, int]) -> int:
        """
        Calculate confidence in the risk assessment
        More analysis components = higher confidence
        """
        
        num_components = len(component_scores)
        
        # Base confidence on number of analysis components
        if num_components >= 4:
            base_confidence = 95
        elif num_components == 3:
            base_confidence = 85
        elif num_components == 2:
            base_confidence = 70
        elif num_components == 1:
            base_confidence = 50
        else:
            base_confidence = 30
        
        # Adjust based on score variance
        if num_components > 1:
            scores = list(component_scores.values())
            avg_score = sum(scores) / len(scores)
            variance = sum((s - avg_score) ** 2 for s in scores) / len(scores)
            
            # High variance means inconsistent signals, lower confidence
            if variance > 400:  # scores differ by more than 20 points
                base_confidence -= 15
        
        return min(100, max(0, base_confidence))
    
    def _generate_recommendations(
        self,
        score: int,
        risk_level: str,
        component_scores: Dict[str, int],
        threat_indicators: List[str]
    ) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        
        recommendations = []
        
        # Primary recommendation based on risk level
        if risk_level == 'CRITICAL':
            recommendations.append('⛔ DO NOT INTERACT - This is almost certainly a phishing attempt')
            recommendations.append('Delete this email/avoid this URL immediately')
            recommendations.append('Report to your IT security team if received at work')
            
        elif risk_level == 'HIGH':
            recommendations.append('⚠️ HIGH RISK - Likely phishing attempt')
            recommendations.append('Do not click any links or provide any information')
            recommendations.append('Verify through official channels if this claims to be from a known organization')
            
        elif risk_level == 'MEDIUM':
            recommendations.append('⚡ MEDIUM RISK - Exercise caution')
            recommendations.append('Verify the sender through alternative means before taking action')
            recommendations.append('Do not provide sensitive information')
            recommendations.append('Check the URL carefully if you must visit it')
            
        else:  # LOW
            recommendations.append('✓ LOW RISK - Appears relatively safe')
            recommendations.append('Still exercise standard security practices')
            recommendations.append('Verify sender identity if requesting sensitive actions')
        
        # Specific recommendations based on component scores
        if component_scores.get('url', 0) > 60:
            recommendations.append('🔗 URL shows multiple red flags - do not visit')
        
        if component_scores.get('email', 0) > 60:
            recommendations.append('📧 Email content contains phishing indicators')
        
        if component_scores.get('hibp', 0) > 0:
            recommendations.append('🔓 Email address found in data breaches - change your passwords')
        
        # Specific threat-based recommendations
        threat_text = ' '.join(threat_indicators).lower()
        
        if 'password' in threat_text or 'credentials' in threat_text:
            recommendations.append('🔐 Never provide passwords via email or unfamiliar websites')
        
        if 'payment' in threat_text or 'bank' in threat_text or 'credit card' in threat_text:
            recommendations.append('💳 Never provide financial information unless verified')
        
        if 'urgent' in threat_text or 'immediate' in threat_text:
            recommendations.append('⏰ Urgency is a common phishing tactic - take time to verify')
        
        return recommendations
    
    def get_risk_summary(self, results: Dict[str, Any]) -> str:
        """
        Generate a human-readable risk summary
        
        Args:
            results: Overall risk assessment results
            
        Returns:
            Formatted summary string
        """
        score = results['risk_score']
        level = results['risk_level']
        confidence = results['confidence']
        
        # Color coding
        level_emoji = {
            'LOW': '✅',
            'MEDIUM': '⚠️',
            'HIGH': '🚨',
            'CRITICAL': '⛔'
        }
        
        summary = f"\n{level_emoji.get(level, '❓')} PHISHING ANALYSIS RESULTS\n"
        summary += "=" * 50 + "\n\n"
        summary += f"Risk Score: {score}/100\n"
        summary += f"Risk Level: {level}\n"
        summary += f"Confidence: {confidence}%\n\n"
        
        # Component breakdown
        if results.get('component_scores'):
            summary += "Component Scores:\n"
            for component, comp_score in results['component_scores'].items():
                summary += f"  • {component.upper()}: {comp_score}/100\n"
            summary += "\n"
        
        # Threat indicators
        threat_count = len(results.get('threat_indicators', []))
        if threat_count > 0:
            summary += f"Threat Indicators ({threat_count}):\n"
            for indicator in results['threat_indicators'][:10]:
                summary += f"  ✗ {indicator}\n"
            if threat_count > 10:
                summary += f"  ... and {threat_count - 10} more\n"
            summary += "\n"
        
        # Recommendations
        if results.get('recommendations'):
            summary += "Recommendations:\n"
            for rec in results['recommendations']:
                summary += f"  {rec}\n"
        
        summary += "\n" + "=" * 50 + "\n"
        
        return summary
