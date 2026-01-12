# Quick Start Guide

Get up and running with AI-Powered Phishing Analyzer in 5 minutes!

## 1. Setup (2 minutes)

```bash
cd AI-Phishing-Analyzer
./setup.sh
```

This will:
- Create virtual environment
- Install all dependencies
- Download NLP data
- Create config file

## 2. Configure API Keys (1 minute)

Edit `config.yaml`:

```bash
nano config.yaml
```

Add your OpenAI API key:
```yaml
openai_api_key: "sk-your-key-here"
```

**Don't have an API key?** The tool works without it, but AI analysis will be disabled.

Get a free key at: https://platform.openai.com/api-keys

## 3. Run Your First Analysis (1 minute)

### Option A: Use GUI (Easiest)

```bash
./run_gui.sh
```

1. Enter a URL or email text
2. Click "🔍 ANALYZE"
3. View results!

### Option B: Use CLI

**Test with a sample phishing email:**
```bash
./run_cli.sh --email-file samples/phishing_email.txt
```

**Test with a URL:**
```bash
./run_cli.sh --url https://example.com
```

## 4. Understanding Results

### Risk Levels

- 🟢 **LOW (0-25)**: Safe, minimal concerns
- 🟡 **MEDIUM (26-50)**: Be cautious
- 🔴 **HIGH (51-75)**: Likely phishing
- 🟣 **CRITICAL (76-100)**: Definitely phishing - avoid!

### What to Look For

**Threat Indicators** = Red flags detected
**Recommendations** = What you should do

## Common Commands

```bash
# Analyze URL
./run_cli.sh --url https://suspicious-site.com

# Analyze email
./run_cli.sh --email "Your email text here"

# Load email from file
./run_cli.sh --email-file email.txt

# Fast analysis (no AI)
./run_cli.sh --url example.com --no-llm

# Save results
./run_cli.sh --url example.com --output results.json

# Get help
./run_cli.sh --help
```

## Testing

Try these test files:

```bash
# Phishing email (should score HIGH/CRITICAL)
./run_cli.sh --email-file samples/phishing_email.txt

# Legitimate email (should score LOW/MEDIUM)
./run_cli.sh --email-file samples/legitimate_email.txt

# Mixed URLs (batch test)
./run_cli.sh --batch samples/test_urls.txt
```

## Troubleshooting

### "Command not found"
```bash
chmod +x setup.sh run_cli.sh run_gui.sh
```

### "Module not found"
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### "API Error"
- Check your API key in config.yaml
- Or run with `--no-llm` flag

## Next Steps

- Read the full [README.md](README.md)
- Check [USAGE_GUIDE.md](USAGE_GUIDE.md) for advanced features
- Try analyzing real suspicious emails
- Customize config.yaml for your needs

## Need Help?

- Check the documentation
- Review sample files in `samples/`
- Open an issue on GitHub

## Stay Safe! 🛡️

Remember: This tool is one layer of defense. Always:
- Think before you click
- Verify sender identity
- Use strong, unique passwords
- Enable 2FA where possible

---

**Total setup time: ~5 minutes**
**First analysis: ~10 seconds**

Happy phishing hunting! 🎣🚫
