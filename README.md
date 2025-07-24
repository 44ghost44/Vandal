# Vandal - Advanced Web Vulnerability Scanner

Vandal it's advanced security scanner for web URLs.  
It tests for XSS, SQL Injection, missing security headers, discovers subdomains, and finds Wayback Machine URLs.

**Author:** 44ghost44

## Features

- Detects reflected XSS and advanced SQL Injection vulnerabilities
- Checks for missing security headers (CSP, HSTS, etc)
- Enumerates subdomains using crt.sh
- Harvests historical URLs from Wayback Machine
- Colorful CLI output with progress bars
- Fast or full scan modes

## Requirements

- Python 3.8+
- Install dependencies with:

```
pip install -r requirements.txt
```

## Usage

```
python3 test.py [url1] [url2] ... [--full]
```

- Default mode is fast. Use `--full` for comprehensive testing.
- You will be prompted for a custom User-Agent and scan delay.
```

## Update dependencies

```
python3 test.py --update
```

## Disclaimer

```
WARNING: Only for ethical and legal use. The author is not responsible for misuse.
```

---

Made with ❤️ by 44ghost44
