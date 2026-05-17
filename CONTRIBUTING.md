# Contributing to AFIR-TI

Thank you for considering contributing to AFIR-TI! This document provides guidelines for contributing.

## 🎯 How Can I Contribute?

### Reporting Bugs
- Use the bug report template
- Include steps to reproduce
- Provide environment details

### Suggesting Features
- Use the feature request template
- Describe the use case
- Explain expected behavior

### Code Contributions
1. Fork the repository
2. Create a branch from `develop`
3. Make your changes
4. Write/update tests
5. Submit a pull request

## 📋 Pull Request Guidelines

### Before Submitting
- [ ] Code follows existing style
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No sensitive data committed

### PR Title Format
```
[TYPE] Description
```
Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example: `feat: Add new correlation algorithm`

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=.

# Run specific test file
pytest tests/test_correlation.py
```

## 📝 Coding Standards

### Python Style
- Follow PEP 8
- Use type hints
- Add docstrings
- Maximum line length: 127 characters

### Example Function
```python
def detect_threat(events: List[Dict], threshold: float = 0.5) -> List[Dict]:
    """
    Detect threats from event list.
    
    Args:
        events: List of security events
        threshold: Detection threshold (0-1)
    
    Returns:
        List of detected threats
    
    Raises:
        ValueError: If threshold is out of range
    """
    if not 0 <= threshold <= 1:
        raise ValueError("Threshold must be between 0 and 1")
    
    return [e for e in events if e['score'] > threshold]
```

## 🔒 Security Guidelines

- Never commit API keys or credentials
- Sanitize all user inputs
- Validate IP addresses
- Use parameterized queries

## 📞 Questions?

Open an issue with the `question` label or contact the maintainer.

---

Thanks for contributing! 🚀
