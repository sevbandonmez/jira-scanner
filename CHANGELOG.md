# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2024-01-01

### Added
- Comprehensive CVE detection for multiple Jira vulnerabilities
- Advanced security checks including SSRF, XSS, and authentication bypass
- Cloud metadata testing for AWS, GCP, Azure, and other providers
- Information disclosure testing
- SQL injection vulnerability assessment
- File upload vulnerability detection
- API endpoint exposure analysis
- Backup file detection
- Debug endpoint identification
- Comprehensive reporting in JSON and text formats
- Multi-threaded scanning for improved performance
- Random user agent generation to avoid detection
- Retry logic for failed requests
- SSL verification options
- Authentication support via cookies
- Batch scanning from file
- Color-coded terminal output
- Docker support
- Makefile for easy operations

### Changed
- Improved error handling and logging
- Enhanced version detection methods
- Better URL normalization and cleaning
- More robust request handling

### Fixed
- SSL warning suppression
- Request timeout handling
- URL parsing issues

## [2.0.0] - 2023-12-01

### Added
- Basic Jira security scanning functionality
- Version detection
- Simple vulnerability checks

### Changed
- Initial release with core features

## [1.0.0] - 2023-11-01

### Added
- Project initialization
- Basic structure setup
