# AI_Phishing_Analyzer
# 🛡️ AI-Powered Phishing Analyzer

An advanced phishing detection system that leverages artificial intelligence, natural language processing, and multiple security APIs to analyze URLs and emails for potential phishing threats.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## 🌟 Features

### Comprehensive URL Analysis
- **Domain Age Verification**: Checks WHOIS data to identify newly registered domains (common in phishing)
- **SSL Certificate Validation**: Verifies certificate validity, issuer, and expiration
- **DNS Analysis**: Checks MX records and suspicious DNS patterns
- **Blacklist Checking**: Cross-references against known malicious domains
- **URL Pattern Detection**: Identifies suspicious URL structures and typosquatting

### Advanced Email Analysis
- **Sentiment Analysis**: Uses NLP to detect urgency, fear, and manipulation tactics
- **Tone Detection via LLM**: OpenAI API integration to identify aggressive/threatening language
- **Suspicious Pattern Recognition**: Detects common phishing keywords and phrases
- **Header Analysis**: Examines sender information and email headers
- **Link Extraction**: Analyzes all embedded URLs

### Security Integrations
- **Have I Been Pwned API**: Check if email addresses have been compromised
- **OpenAI GPT Integration**: Advanced linguistic analysis for sophisticated threats
- **Real-time Threat Intelligence**: Multiple API integrations for up-to-date threat data

### AI-Powered Risk Scoring
- Multi-factor risk assessment combining all analysis components
- Weighted scoring system based on threat indicators
- Clear risk categorization: Low, Medium, High, Critical

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Internet connection for API calls

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/AI-Phishing-Analyzer.git
cd AI-Phishing-Analyzer

# Run the automated setup script
chmod +x setup.sh
./setup.sh
```

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

1. Copy the example configuration file:
```bash
cp config.example.yaml config.yaml
```

2. Edit `config.yaml` and add your API keys:
```yaml
openai_api_key: "your-openai-api-key-here"
hibp_api_key: "your-haveibeenpwned-api-key-here"  # Optional but recommended
```

**Getting API Keys:**
- OpenAI: https://platform.openai.com/api-keys
- Have I Been Pwned: https://haveibeenpwned.com/API/Key

## 💻 Usage

### GUI Mode (Recommended for beginners)

```bash
python gui.py
```

The GUI provides:
- Easy-to-use interface for URL and email analysis
- Visual risk indicators with color coding
- Detailed breakdown of all analysis components
- Export functionality for reports

### CLI Mode (For automation and scripting)

**Analyze a URL:**
```bash
python cli.py --url https://suspicious-site.com
```

**Analyze email text:**
```bash
python cli.py --email "Urgent! Your account will be closed..."
```

**Analyze email from file:**
```bash
python cli.py --email-file samples/phishing_email.txt
```

**Batch analysis:**
```bash
python cli.py --batch urls.txt --output results.json
```

**Advanced options:**
```bash
python cli.py --url https://example.com --verbose --no-llm --output report.json
```

### Python Module Usage

```python
from phishing_analyzer import PhishingAnalyzer

# Initialize analyzer
analyzer = PhishingAnalyzer(config_path='config.yaml')

# Analyze a URL
url_result = analyzer.analyze_url('https://suspicious-site.com')
print(f"Risk Score: {url_result['risk_score']}/100")
print(f"Risk Level: {url_result['risk_level']}")

# Analyze email text
email_result = analyzer.analyze_email(email_text)
print(f"Threat Indicators: {email_result['threat_indicators']}")
```

## 📊 Understanding Results

### Risk Levels
- **Low (0-25)**: Appears legitimate, minimal threat indicators
- **Medium (26-50)**: Some suspicious elements, proceed with caution
- **High (51-75)**: Multiple red flags, likely phishing attempt
- **Critical (76-100)**: Extreme threat, definitely malicious

### Analysis Components

**URL Analysis includes:**
- Domain registration age
- SSL certificate status
- DNS configuration
- Blacklist presence
- URL structure patterns

**Email Analysis includes:**
- Sentiment score (-1 to 1)
- Detected manipulation tactics
- Suspicious keywords count
- Urgency indicators
- LLM threat assessment

## 🔧 Configuration Options

Edit `config.yaml` to customize:

```yaml
# API Configuration
openai_api_key: "your-key"
openai_model: "gpt-4"  # or "gpt-3.5-turbo" for lower cost
hibp_api_key: "your-key"

# Analysis Settings
risk_thresholds:
  low: 25
  medium: 50
  high: 75

# Feature Toggles
enable_llm_analysis: true
enable_hibp_check: true
enable_dns_check: true

# Timeouts (seconds)
ssl_check_timeout: 10
whois_timeout: 15
api_timeout: 30
```

## 📁 Project Structure

```
AI-Phishing-Analyzer/
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── setup.sh                  # Automated setup script
├── config.example.yaml       # Example configuration
├── config.yaml              # Your configuration (git-ignored)
├── .gitignore               # Git ignore rules
│
├── cli.py                   # Command-line interface
├── gui.py                   # Graphical user interface
│
├── phishing_analyzer/       # Main package
│   ├── __init__.py
│   ├── analyzer.py          # Main analyzer class
│   ├── url_analyzer.py      # URL analysis module
│   ├── email_analyzer.py    # Email analysis module
│   ├── risk_scorer.py       # Risk scoring engine
│   ├── llm_analyzer.py      # LLM integration
│   └── utils.py             # Utility functions
│
├── samples/                 # Example files
│   ├── phishing_email.txt
│   ├── legitimate_email.txt
│   └── test_urls.txt
│
└── tests/                   # Unit tests
    ├── test_analyzer.py
    ├── test_url_analyzer.py
    └── test_email_analyzer.py
```

## 🧪 Examples

### Example 1: Phishing URL Detection

```bash
python cli.py --url "http://paypa1-secure-login.com/verify"
```

**Output:**
```
⚠️  PHISHING ANALYSIS REPORT ⚠️

URL: http://paypa1-secure-login.com/verify
Risk Score: 87/100
Risk Level: CRITICAL

Threat Indicators:
✗ Domain registered 3 days ago
✗ Typosquatting detected (paypa1 vs paypal)
✗ No valid SSL certificate
✗ Domain on blacklist
✗ Suspicious TLD pattern

Recommendation: DO NOT VISIT - High confidence phishing attempt
```

### Example 2: Email Analysis

```bash
python cli.py --email "URGENT: Your account has been compromised! Click here immediately to secure your account or it will be permanently deleted within 24 hours!"
```

**Output:**
```
📧 EMAIL ANALYSIS REPORT

Risk Score: 92/100
Risk Level: CRITICAL

Threat Indicators:
✗ High urgency language detected
✗ Fear-based manipulation tactics
✗ Time pressure (24 hours)
✗ Aggressive tone detected by AI
✗ Contains: "URGENT", "compromised", "immediately", "deleted"

LLM Analysis: "Exhibits classic phishing characteristics including 
urgency, fear tactics, and threatening language designed to bypass 
rational decision-making."

Recommendation: DELETE - Likely phishing attempt
```

## 🔒 Privacy & Security

- **No Data Storage**: Analysis is performed in real-time; no data is stored
- **API Privacy**: Only sends text to OpenAI; no personal data collection
- **Local Processing**: Most analysis done locally on your machine
- **Open Source**: Full transparency - review the code yourself

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- OpenAI for GPT API
- Have I Been Pwned for breach data
- NLTK for NLP capabilities
- The cybersecurity community for threat intelligence

## ⚠️ Disclaimer

This tool is designed to assist in identifying potential phishing attempts but should not be the only line of defense. Always practice good security hygiene:
- Never click suspicious links
- Verify sender identity through official channels
- Use 2FA wherever possible
- Keep software updated
- When in doubt, don't click

## 📞 Support

- Report bugs: [GitHub Issues](https://github.com/yourusername/AI-Phishing-Analyzer/issues)
- Documentation: [Wiki](https://github.com/yourusername/AI-Phishing-Analyzer/wiki)
- Email: your.email@example.com

## 🗺️ Roadmap

- [ ] Machine learning model for pattern recognition
- [ ] Browser extension
- [ ] Mobile app version
- [ ] Real-time email plugin (Gmail, Outlook)
- [ ] Expanded language support
- [ ] Community threat intelligence sharing
- [ ] Integration with SIEM systems

---

**Stay Safe Online! 🛡️**
