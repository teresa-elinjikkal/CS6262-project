# CS6262 Project: Evaluating the Network Security Infrastructure of Public School Districts

## Security Measurements

### Email Security
- SPF record presence and configuration
- DKIM detection using common DNS selectors
- DMARC presence and enforcement policies (`none`, `quarantine`, `reject`)
- DMARC aggregate reporting (RUA)
- Email provider identification using MX records
- MTA-STS and TLS-RPT record detection

### DNS Security
- DNSSEC detection through DS and DNSKEY records

### Web Security
- HTTPS availability and TLS certificate verification
- HTTP-to-HTTPS redirects
- Security headers:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Cookie security attributes:
  - Secure
  - HttpOnly
  - SameSite

### Third-Party Infrastructure
- Email provider identification through MX records
- CDN and reverse-proxy provider detection using DNS CNAME records and HTTP response headers
- TLS certificate authority identification
- TLS certificate issuer and expiration information
