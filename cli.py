#!/usr/bin/env python3
"""
Command Line Interface for AI Phishing Analyzer
"""

import sys
import argparse
import json
from pathlib import Path
from phishing_analyzer import PhishingAnalyzer


def print_banner():
    """Print application banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        🛡️  AI-Powered Phishing Analyzer 🛡️                  ║
║                                                               ║
║     Advanced URL & Email Phishing Detection System            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_results(results, verbose=False):
    """
    Print analysis results in a readable format
    
    Args:
        results: Analysis results dictionary
        verbose: Whether to show detailed information
    """
    # Risk level colors (using ANSI escape codes)
    colors = {
        'LOW': '\033[92m',      # Green
        'MEDIUM': '\033[93m',   # Yellow
        'HIGH': '\033[91m',     # Red
        'CRITICAL': '\033[95m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    risk_level = results.get('risk_level', 'UNKNOWN')
    risk_score = results.get('risk_score', 0)
    color = colors.get(risk_level, colors['RESET'])
    
    print("\n" + "=" * 70)
    print(f"{color}RISK ASSESSMENT: {risk_level} ({risk_score}/100){colors['RESET']}")
    print("=" * 70)
    
    # Analysis type
    analysis_type = results.get('analysis_type', 'unknown')
    print(f"\nAnalysis Type: {analysis_type.upper()}")
    
    if analysis_type == 'url':
        print(f"URL Analyzed: {results.get('input', 'N/A')}")
    elif analysis_type == 'email':
        print(f"Email Length: {results.get('input_length', 0)} characters")
    
    # Overall risk info
    if results.get('overall_risk'):
        overall = results['overall_risk']
        confidence = overall.get('confidence', 0)
        print(f"Confidence: {confidence}%")
        
        # Component scores
        if verbose and overall.get('component_scores'):
            print("\nComponent Scores:")
            for component, score in overall['component_scores'].items():
                print(f"  • {component.upper()}: {score}/100")
    
    # Threat indicators
    threat_indicators = results.get('threat_indicators', [])
    if threat_indicators:
        print(f"\n⚠️  THREAT INDICATORS ({len(threat_indicators)}):")
        for i, indicator in enumerate(threat_indicators[:15], 1):
            print(f"  {i}. {indicator}")
        if len(threat_indicators) > 15:
            print(f"  ... and {len(threat_indicators) - 15} more")
    
    # Safe indicators
    if verbose:
        safe_indicators = results.get('overall_risk', {}).get('safe_indicators', [])
        if safe_indicators:
            print(f"\n✓ SAFE INDICATORS ({len(safe_indicators)}):")
            for indicator in safe_indicators[:10]:
                print(f"  • {indicator}")
    
    # Recommendations
    recommendations = results.get('recommendations', [])
    if recommendations:
        print(f"\n📋 RECOMMENDATIONS:")
        for rec in recommendations:
            print(f"  {rec}")
    
    # LLM Analysis
    if verbose and results.get('llm_analysis', {}).get('available'):
        llm = results['llm_analysis']
        print("\n🤖 AI ANALYSIS:")
        if llm.get('summary'):
            print(f"  {llm['summary']}")
        if llm.get('tone_analysis'):
            print(f"  Tone: {llm['tone_analysis'][:200]}")
    
    # Tone Analysis
    if verbose and results.get('tone_analysis', {}).get('available'):
        tone = results['tone_analysis']
        print("\n🎭 TONE ANALYSIS:")
        print(f"  Manipulation Score: {tone.get('manipulation_score', 'N/A')}/10")
        if tone.get('is_aggressive'):
            print("  ⚠️  Aggressive or threatening tone detected")
    
    # HIBP Results
    if results.get('hibp_results', {}).get('is_breached'):
        hibp = results['hibp_results']
        breach_count = hibp.get('breach_count', 0)
        print(f"\n🔓 BREACH ALERT: Email found in {breach_count} data breach(es)")
        if verbose and hibp.get('breaches'):
            for breach in hibp['breaches'][:3]:
                print(f"  • {breach['name']} ({breach['breach_date']})")
    
    # Extracted URLs
    if verbose and results.get('extracted_urls'):
        urls = results['extracted_urls']
        print(f"\n🔗 EXTRACTED URLs ({len(urls)}):")
        for url in urls[:5]:
            print(f"  • {url}")
    
    print("\n" + "=" * 70 + "\n")


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='AI-Powered Phishing Analyzer - Detect phishing in URLs and emails',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://suspicious-site.com
  %(prog)s --email "Urgent! Your account will be closed..."
  %(prog)s --email-file phishing_email.txt
  %(prog)s --batch urls.txt --output results.json
  %(prog)s --url example.com --verbose --no-llm
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--url',
        type=str,
        help='URL to analyze'
    )
    input_group.add_argument(
        '--email',
        type=str,
        help='Email text to analyze'
    )
    input_group.add_argument(
        '--email-file',
        type=str,
        help='Path to file containing email text'
    )
    input_group.add_argument(
        '--batch',
        type=str,
        help='Path to file containing multiple URLs (one per line)'
    )
    
    # Analysis options
    parser.add_argument(
        '--no-llm',
        action='store_true',
        help='Disable LLM analysis (faster but less accurate)'
    )
    parser.add_argument(
        '--no-hibp',
        action='store_true',
        help='Disable Have I Been Pwned checking'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Path to configuration file (default: config.yaml)'
    )
    
    # Output options
    parser.add_argument(
        '--output',
        '-o',
        type=str,
        help='Output file for results (JSON format)'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Show detailed analysis information'
    )
    parser.add_argument(
        '--quiet',
        '-q',
        action='store_true',
        help='Minimal output (only risk score and level)'
    )
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress banner display'
    )
    
    args = parser.parse_args()
    
    # Print banner unless suppressed
    if not args.no_banner and not args.quiet:
        print_banner()
    
    # Initialize analyzer
    try:
        analyzer = PhishingAnalyzer(config_path=args.config)
        
        if not args.quiet:
            print("🔧 Initializing analyzer...")
            stats = analyzer.get_stats()
            print(f"   LLM: {'✓ Enabled' if stats['llm_enabled'] and stats['llm_available'] else '✗ Disabled'}")
            print(f"   HIBP: {'✓ Enabled' if stats['hibp_enabled'] else '✗ Disabled'}")
            print()
    except Exception as e:
        print(f"❌ Error initializing analyzer: {e}", file=sys.stderr)
        return 1
    
    # Process input
    results = None
    
    try:
        if args.url:
            # Analyze single URL
            if not args.quiet:
                print(f"🔍 Analyzing URL: {args.url}")
            results = analyzer.analyze_url(
                args.url,
                use_llm=not args.no_llm
            )
        
        elif args.email:
            # Analyze email text
            if not args.quiet:
                print("🔍 Analyzing email content...")
            results = analyzer.analyze_email(
                args.email,
                use_llm=not args.no_llm,
                check_hibp=not args.no_hibp
            )
        
        elif args.email_file:
            # Read email from file
            email_file = Path(args.email_file)
            if not email_file.exists():
                print(f"❌ Error: File not found: {args.email_file}", file=sys.stderr)
                return 1
            
            if not args.quiet:
                print(f"📄 Reading email from: {args.email_file}")
            
            with open(email_file, 'r', encoding='utf-8') as f:
                email_text = f.read()
            
            results = analyzer.analyze_email(
                email_text,
                use_llm=not args.no_llm,
                check_hibp=not args.no_hibp
            )
        
        elif args.batch:
            # Batch analysis
            batch_file = Path(args.batch)
            if not batch_file.exists():
                print(f"❌ Error: File not found: {args.batch}", file=sys.stderr)
                return 1
            
            with open(batch_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not args.quiet:
                print(f"📦 Starting batch analysis of {len(urls)} URLs...")
            
            results = analyzer.batch_analyze_urls(urls, use_llm=not args.no_llm)
            
            # Print summary for batch
            if not args.quiet:
                print(f"\n✓ Completed: {results['completed']}/{results['total_urls']}")
                print(f"✗ Failed: {results['failed']}/{results['total_urls']}")
                
                # Show risk distribution
                risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
                for url_result in results['results'].values():
                    if not url_result.get('error'):
                        level = url_result.get('risk_level', 'UNKNOWN')
                        risk_counts[level] = risk_counts.get(level, 0) + 1
                
                print("\nRisk Distribution:")
                for level, count in risk_counts.items():
                    if count > 0:
                        print(f"  {level}: {count}")
    
    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"❌ Error during analysis: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    # Display results
    if results:
        if args.quiet:
            # Minimal output
            if 'risk_score' in results:
                print(f"{results['risk_level']}: {results['risk_score']}/100")
        else:
            # Full output
            if args.batch:
                # For batch, just show we're done (detailed results in JSON)
                if not args.output:
                    print("\n💡 Tip: Use --output to save detailed results to JSON file")
            else:
                print_results(results, verbose=args.verbose)
        
        # Save to file if requested
        if args.output:
            try:
                output_path = Path(args.output)
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"💾 Results saved to: {args.output}")
            except Exception as e:
                print(f"❌ Error saving results: {e}", file=sys.stderr)
                return 1
    
    # Return exit code based on risk level
    if results and 'risk_level' in results:
        risk_level = results['risk_level']
        if risk_level == 'CRITICAL':
            return 2
        elif risk_level == 'HIGH':
            return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
