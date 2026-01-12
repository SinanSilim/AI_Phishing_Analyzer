# Contributing to AI-Powered Phishing Analyzer

Thank you for your interest in contributing to this project! This document provides guidelines for contributing.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version)
- Any error messages or logs

### Suggesting Features

Feature requests are welcome! Please include:
- Clear description of the feature
- Use case and benefits
- Any implementation ideas

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add comments for complex logic
   - Update documentation if needed

4. **Test your changes**
   ```bash
   python tests/test_analyzer.py
   ```

5. **Commit with clear messages**
   ```bash
   git commit -m "Add feature: description"
   ```

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/AI-Phishing-Analyzer.git
cd AI-Phishing-Analyzer

# Run setup
./setup.sh

# Activate virtual environment
source venv/bin/activate

# Run tests
python tests/test_analyzer.py
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Add docstrings to functions and classes
- Keep functions focused and concise
- Use meaningful variable names

## Testing

- Add tests for new features
- Ensure existing tests pass
- Test with and without API keys
- Test error handling

## Areas for Contribution

### High Priority
- Additional phishing patterns and keywords
- More blacklist sources integration
- Improved machine learning models
- Browser extension development
- Mobile app version

### Medium Priority
- Additional language support
- More comprehensive testing
- Performance optimizations
- UI/UX improvements
- Documentation improvements

### Low Priority
- Additional export formats
- Integration with other tools
- Custom themes for GUI
- Statistics and analytics features

## Phishing Patterns

When adding new phishing detection patterns:

1. **Document the pattern**: Why is it suspicious?
2. **Provide examples**: Real-world cases
3. **Test thoroughly**: Avoid false positives
4. **Update weights**: Consider impact on risk score

## API Integrations

When adding new API integrations:

1. **Make it optional**: Should work without the API
2. **Handle errors gracefully**: Network issues, rate limits
3. **Respect rate limits**: Implement proper delays
4. **Document setup**: How to get API keys
5. **Consider privacy**: What data is sent

## Documentation

- Update README.md for major features
- Add usage examples
- Update USAGE_GUIDE.md for new functionality
- Keep code comments current

## Questions?

Feel free to:
- Open an issue for discussion
- Join our community discussions
- Contact the maintainers

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow project guidelines

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to make the internet safer! 🛡️
