# AI-Powered Phishing Analyzer - Usage Guide

## Quick Start

### 1. Installation

```bash
# Clone or download the repository
cd AI-Phishing-Analyzer

# Run the setup script
chmod +x setup.sh
./setup.sh
```

### 2. Configuration

Edit `config.yaml` and add your API keys:

```yaml
openai_api_key: "sk-your-key-here"  # For AI analysis
hibp_api_key: "your-key-here"       # Optional
```

**Getting API Keys:**
- **OpenAI**: Visit https://platform.openai.com/api-keys
  - Sign up/login → Create new secret key
  - Cost: ~$0.002 per analysis with gpt-4o-mini
  
- **Have I Been Pwned** (Optional): Visit https://haveibeenpwned.com/API/Key
  - One-time payment for API access
  - Provides breach checking functionality

## Using the GUI (Recommended for Beginners)

### Starting the GUI

```bash
./run_gui.sh
# or
python3 gui.py
```

### GUI Features

1. **Analysis Type Selection**
   - Choose between URL or Email analysis
   
2. **Input Methods**
   - Type/paste directly into the text field
   - Load from file using "Load from File" button
   
3. **Options**
   - **Use AI Analysis**: Enable/disable LLM analysis (requires API key)
   - **Check Data Breaches**: Enable/disable HIBP checking
   - **Verbose Output**: Show detailed analysis information
   
4. **Results Display**
   - Visual risk indicator with color coding
   - Detailed threat indicators and recommendations
   - Export results to JSON for documentation

### GUI Tips

- **Color Coding:**
  - 🟢 Green = Low Risk (0-25)
  - 🟡 Yellow = Medium Risk (26-50)
  - 🔴 Red = High Risk (51-75)
  - 🟣 Purple = Critical Risk (76-100)

- **Performance:**
  - Analysis typically takes 5-15 seconds
  - LLM analysis adds 3-5 seconds
  - Disable AI analysis for faster results

## Using the CLI (For Advanced Users)

### Basic Commands

**Analyze a URL:**
```bash
./run_cli.sh --url https://suspicious-site.com
```

**Analyze email text:**
```bash
./run_cli.sh --email "Your urgent message text here..."
```

**Analyze email from file:**
```bash
./run_cli.sh --email-file samples/phishing_email.txt
```

**Batch analyze multiple URLs:**
```bash
./run_cli.sh --batch samples/test_urls.txt --output results.json
```

### CLI Options

**Analysis Options:**
- `--url URL` - Analyze a URL
- `--email TEXT` - Analyze email text
- `--email-file FILE` - Analyze email from file
- `--batch FILE` - Batch analyze URLs from file

**Feature Toggles:**
- `--no-llm` - Disable AI analysis (faster)
- `--no-hibp` - Disable breach checking
- `--config FILE` - Use custom config file

**Output Options:**
- `--output FILE` - Save results to JSON file
- `--verbose` - Show detailed information
- `--quiet` - Minimal output (score only)
- `--no-banner` - Suppress banner

### CLI Examples

**Quick URL check:**
```bash
./run_cli.sh --url http://paypal-verify.tk
```

**Detailed email analysis with export:**
```bash
./run_cli.sh --email-file suspicious.txt --verbose --output report.json
```

**Fast batch analysis without AI:**
```bash
./run_cli.sh --batch urls.txt --no-llm --output batch_results.json
```

**Quiet mode for scripting:**
```bash
./run_cli.sh --url example.com --quiet --no-banner
# Output: HIGH: 75/100
```

## Using as Python Module

### Basic Usage

```python
from phishing_analyzer import PhishingAnalyzer

# Initialize
analyzer = PhishingAnalyzer('config.yaml')

# Analyze URL
url_result = analyzer.analyze_url('https://suspicious-site.com')
print(f"Risk Score: {url_result['risk_score']}/100")
print(f"Risk Level: {url_result['risk_level']}")

# Analyze Email
email_result = analyzer.analyze_email(email_text)
for indicator in email_result['threat_indicators']:
    print(f"⚠️  {indicator}")
```

### Advanced Usage

```python
from phishing_analyzer import PhishingAnalyzer

analyzer = PhishingAnalyzer()

# Analyze with specific options
result = analyzer.analyze_email(
    email_text,
    email_headers={'from': 'sender@example.com'},
    use_llm=True,
    check_hibp=True
)

# Get human-readable summary
summary = analyzer.get_summary(result)
print(summary)

# Batch analysis
urls = ['url1.com', 'url2.com', 'url3.com']
batch_results = analyzer.batch_analyze_urls(urls, use_llm=False)

for url, result in batch_results['results'].items():
    print(f"{url}: {result['risk_level']}")
```

### Quick Analysis Function

```python
from phishing_analyzer import quick_analyze

# One-liner analysis
result = quick_analyze("https://suspicious-site.com")
print(result['risk_level'])
```

## Understanding Results

### Risk Scores

- **0-25 (Low)**: Appears legitimate, minimal concerns
- **26-50 (Medium)**: Some suspicious elements, be cautious
- **51-75 (High)**: Multiple red flags, likely phishing
- **76-100 (Critical)**: Extreme threat, definitely avoid

### Threat Indicators

Common indicators you'll see:

**URL-Related:**
- Domain registered recently (< 30 days)
- Typosquatting detected (e.g., "paypa1" vs "paypal")
- No valid SSL certificate
- Uses suspicious TLD (.tk, .ml, .ga)
- IP address instead of domain name

**Email-Related:**
- High urgency language
- Threatening or aggressive tone
- Requests for personal information
- Contains suspicious keywords
- Poor grammar/composition
- Multiple URLs or redirects

**Security-Related:**
- Email found in data breaches (HIBP)
- Domain on blacklist
- Mismatched sender domains
- Display name spoofing

### Recommendations

Follow the recommendations provided:
- **⛔ DO NOT INTERACT**: Critical risk - avoid completely
- **⚠️ HIGH RISK**: Do not click links or provide information
- **⚡ MEDIUM RISK**: Verify through official channels
- **✓ LOW RISK**: Still use standard security practices

## Common Use Cases

### 1. Checking Suspicious Emails

**Scenario:** Received an email claiming to be from your bank

**Steps:**
1. Open the GUI
2. Select "Email" analysis type
3. Copy the entire email text
4. Paste into the input field
5. Enable all analysis options
6. Click "ANALYZE"
7. Review threat indicators and recommendations

### 2. Verifying URLs Before Clicking

**Scenario:** Got a shortened URL in a message

**Steps:**
1. Copy the URL (don't click it!)
2. Use CLI: `./run_cli.sh --url https://bit.ly/xxxxxx`
3. Review the risk score
4. If safe, you can visit; if high risk, avoid

### 3. Training Employees (IT Security)

**Scenario:** Training staff to recognize phishing

**Steps:**
1. Prepare sample emails (phishing + legitimate)
2. Use batch CLI: `./run_cli.sh --batch emails.txt --output training_results.json`
3. Review results with team
4. Discuss threat indicators
5. Use as ongoing training tool

### 4. Security Auditing

**Scenario:** Audit organization's exposed data

**Steps:**
1. Collect email addresses
2. Use Python module with HIBP integration
3. Generate report of breached accounts
4. Recommend password changes
5. Document findings

## Troubleshooting

### "Analyzer not initialized" Error

**Solution:** Check if config.yaml exists and is valid
```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your settings
```

### "OpenAI API Error"

**Solutions:**
- Verify API key is correct in config.yaml
- Check you have API credits
- Try using `--no-llm` flag as workaround
- Use gpt-4o-mini model (cheaper)

### "ModuleNotFoundError"

**Solution:** Reinstall dependencies
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Slow Analysis

**Solutions:**
- Disable LLM with `--no-llm`
- Disable HIBP with `--no-hibp`
- Check internet connection
- Use batch mode for multiple URLs

### "Permission Denied" on Scripts

**Solution:** Make scripts executable
```bash
chmod +x setup.sh run_cli.sh run_gui.sh
```

## Best Practices

### For Individual Use

1. **Always verify suspicious emails** before taking action
2. **Never disable all security checks** without good reason
3. **Keep API keys secure** - never commit config.yaml to git
4. **Update regularly** to get latest threat intelligence
5. **Combine with other tools** - this is one layer of defense

### For Organizations

1. **Deploy centrally** for consistent analysis
2. **Integrate with email gateway** for automatic scanning
3. **Train users** on interpreting results
4. **Document policies** based on risk levels
5. **Monitor API usage** and costs
6. **Regular updates** to wordlists and patterns

### For Developers

1. **Use Python module** for integration
2. **Cache results** to avoid redundant API calls
3. **Implement rate limiting** for public deployments
4. **Add custom wordlists** for your domain
5. **Extend with custom analyzers** for specific threats

## Performance Tips

### Optimize for Speed

```python
# Disable expensive checks for quick screening
analyzer.config['enable_whois_check'] = False
analyzer.config['enable_dns_check'] = False

# Use faster model
analyzer.config['openai_model'] = 'gpt-3.5-turbo'

# Batch processing
results = analyzer.batch_analyze_urls(urls, use_llm=False)
```

### Optimize for Accuracy

```python
# Enable all checks
analyzer.config['enable_llm_analysis'] = True
analyzer.config['enable_hibp_check'] = True
analyzer.config['enable_whois_check'] = True

# Use best model
analyzer.config['openai_model'] = 'gpt-4'
```

## Security Considerations

### What We Send to APIs

**OpenAI API:**
- Email text content (for analysis)
- URL strings
- NO personal data, passwords, or credentials

**Have I Been Pwned API:**
- Email addresses only (with k-anonymity for passwords)
- NO passwords in clear text

### Privacy

- No data is stored by this tool
- All analysis is real-time
- API providers have their own privacy policies
- Consider self-hosting for sensitive use cases

## Support & Resources

- **Issues**: Report bugs via GitHub Issues
- **Documentation**: Full docs in README.md
- **Examples**: See samples/ directory
- **Tests**: Run `python tests/test_analyzer.py`

## License

MIT License - See LICENSE file for details
