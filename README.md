# Advanced Jira Security Assessment Tool

A comprehensive security scanner for Jira instances that detects various vulnerabilities, information disclosures, and security misconfigurations.

## Features

- **CVE Detection**: Tests for known Jira vulnerabilities including:
  - CVE-2017-9506 (SSRF via OAuth)
  - CVE-2019-8451 (SSRF via gadget rendering)
  - CVE-2019-3396 (Path Traversal/RCE)
  - CVE-2019-11581 (Server Side Template Injection)
  - CVE-2019-8449 (User enumeration)
  - CVE-2018-20824 (XSS in Wallboard)
  - CVE-2020-14179 (Information disclosure)
  - CVE-2020-14181 (User enumeration)

- **Advanced Security Checks**:
  - Information disclosure testing
  - Authentication bypass detection
  - SQL injection testing
  - File upload vulnerability assessment
  - Blind SSRF testing
  - API endpoint exposure analysis
  - Backup file detection
  - Debug endpoint identification

- **Cloud Metadata Testing**: Detects access to cloud provider metadata (AWS, GCP, Azure, etc.)

- **Comprehensive Reporting**: Generates both JSON and text reports with detailed findings

## Installation

1. Clone the repository:
```bash
git clone [<repository-url>](https://github.com/sevbandonmez/jira-scanner.git)
cd jira-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Scan a single Jira instance:
```bash
python3 jira-scanner.py -u https://jira.example.com
```

Scan multiple targets from a file:
```bash
python3 jira-scanner.py -f urls.txt
```

### Advanced Options

```bash
python3 jira-scanner.py -u https://jira.example.com \
  -c "JSESSIONID=ABC123" \
  -o reports/ \
  -i \
  -t 30 \
  -r 5
```

### Command Line Options

- `-u, --url`: Target URL
- `-f, --file`: File containing list of URLs
- `-c, --cookie`: Authentication cookie
- `-o, --output`: Output directory (default: output/)
- `-i, --insecure`: Disable SSL verification
- `-t, --timeout`: Request timeout in seconds (default: 15)
- `-r, --retries`: Number of retries (default: 3)
- `-h, --help`: Show help message

### Examples

1. **Basic scan with SSL verification disabled**:
```bash
python3 jira-scanner.py -u https://jira.example.com -i
```

2. **Scan with authentication**:
```bash
python3 jira-scanner.py -u https://jira.example.com -c "JSESSIONID=ABC123"
```

3. **Batch scan with custom output directory**:
```bash
python3 jira-scanner.py -f urls.txt -o reports/ -i
```

4. **High timeout for slow networks**:
```bash
python3 jira-scanner.py -u https://jira.example.com -t 60 -r 5
```

## Output

The tool generates two types of reports:

1. **JSON Report** (`jira_security_report_YYYYMMDD_HHMMSS.json`): Machine-readable format with all scan details
2. **Text Report** (`jira_security_report_YYYYMMDD_HHMMSS.txt`): Human-readable summary

### Report Structure

```json
{
  "scan_info": {
    "timestamp": "2024-01-01T12:00:00",
    "target_info": {
      "version": "8.20.0",
      "serverTitle": "Jira",
      "buildNumber": "820000"
    },
    "total_vulnerabilities": 5
  },
  "vulnerabilities": [
    {
      "type": "CVE-2017-9506",
      "severity": "CRITICAL",
      "description": "SSRF vulnerability",
      "url": "https://jira.example.com/plugins/servlet/oauth/users/icon-uri",
      "evidence": "...",
      "timestamp": "2024-01-01T12:00:00"
    }
  ],
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1
  }
}
```

## Security Considerations

⚠️ **Important**: This tool is designed for authorized security testing only. Always ensure you have proper authorization before scanning any systems.

- Only use on systems you own or have explicit permission to test
- Be aware of rate limiting and network policies
- Some tests may trigger security alerts
- Consider the impact on production systems

## Vulnerability Severity Levels

- **CRITICAL**: Immediate action required (SSRF, RCE, etc.)
- **HIGH**: Significant security risk (XSS, auth bypass, etc.)
- **MEDIUM**: Moderate security concern (info disclosure, etc.)
- **LOW**: Minor security issue (debug endpoints, etc.)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

- **Author**: sevbandonmez
- **Version**: 1.0

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before using this tool on any system.
