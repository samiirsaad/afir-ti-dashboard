# 🔒 Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. Thank you for disclosing them responsibly.

### How to Report

**Please DO NOT report security vulnerabilities in public GitHub issues.**

Instead, email directly to: [security email or use GitHub's private vulnerability reporting]

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Resolution Target**: Based on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### Security Best Practices for Users

1. **API Keys**: Store in secure location, never commit to version control
2. **Network Exposure**: Do not expose dashboard to public internet without authentication
3. **Root Access**: System requires root for iptables - ensure host is secured
4. **Regular Updates**: Keep dependencies updated
5. **Backup**: Regularly backup `/opt/firewall_irt/` directory
6. **Log Monitoring**: Monitor logs for suspicious activity
7. **Firewall Rules**: Review auto-blocked IPs periodically

## Security Features

- Input validation on all API endpoints
- IP address validation
- Path traversal protection in log viewer
- Safe JSON parsing
- Error handling without information leakage

## Known Limitations

- No built-in authentication (implement reverse proxy for production)
- No rate limiting (implement at network level)
- CORS enabled for all origins (restrict in production)

---

Thank you for helping keep AFIR-TI secure! 🛡️
