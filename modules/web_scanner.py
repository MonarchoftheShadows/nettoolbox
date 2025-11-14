#!/usr/bin/env python3
"""
Web Scanner Module
Handles web application security scanning and reconnaissance

Author: NetTools Team
"""

import requests
import re
import urllib.parse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Set
import time

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebScanner:
    """Web application security scanner."""
    
    def __init__(self):
        """Initialize the web scanner."""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 10
        self.max_threads = 20
        
        # Common directories for brute force
        self.common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'backup', 'backups', 'old', 'tmp', 'temp', 'test', 'dev',
            'staging', 'www', 'web', 'files', 'uploads', 'images',
            'css', 'js', 'assets', 'static', 'public', 'private',
            'api', 'v1', 'v2', 'docs', 'documentation', 'help'
        ]
        
        # Common files
        self.common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'readme.txt', 'readme.html', 'changelog.txt', 'version.txt',
            'phpinfo.php', 'info.php', 'test.php', 'index.bak',
            'backup.sql', 'dump.sql', '.env', 'config.php',
            'wp-config.php', 'database.yml', 'settings.py'
        ]
        
        # XSS payloads for testing
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "';alert('XSS');//",
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")'
        ]
        
        # SQL injection payloads
        self.sqli_payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--"
        ]
    
    def analyze_url(self, url: str) -> Dict:
        """
        Analyze a single URL for basic information.
        
        Args:
            url: Target URL to analyze
            
        Returns:
            Dictionary with URL analysis results
        """
        results = {
            'url': url,
            'status_code': None,
            'headers': {},
            'title': '',
            'forms': [],
            'links': [],
            'technologies': [],
            'security_headers': {}
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            results['status_code'] = response.status_code
            results['headers'] = dict(response.headers)
            
            # Parse HTML content
            if 'text/html' in response.headers.get('content-type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract title
                title_tag = soup.find('title')
                if title_tag:
                    results['title'] = title_tag.get_text().strip()
                
                # Find forms
                results['forms'] = self._extract_forms(soup)
                
                # Find links
                results['links'] = self._extract_links(soup, url)
                
                # Detect technologies
                results['technologies'] = self._detect_technologies(response, soup)
            
            # Check security headers
            results['security_headers'] = self._check_security_headers(response.headers)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract forms from HTML."""
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            # Extract input fields
            for input_field in form.find_all(['input', 'textarea', 'select']):
                field_info = {
                    'name': input_field.get('name', ''),
                    'type': input_field.get('type', 'text'),
                    'value': input_field.get('value', '')
                }
                form_data['inputs'].append(field_info)
            
            forms.append(form_data)
        
        return forms
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract links from HTML."""
        links = set()
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urllib.parse.urljoin(base_url, href)
            
            # Only include HTTP/HTTPS links
            if full_url.startswith(('http://', 'https://')):
                links.add(full_url)
        
        return list(links)[:50]  # Limit to 50 links
    
    def _detect_technologies(self, response: requests.Response, 
                           soup: BeautifulSoup) -> List[str]:
        """Detect web technologies used."""
        technologies = []
        headers = response.headers
        content = response.text.lower()
        
        # Server header
        server = headers.get('server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # X-Powered-By header
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        elif 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        
        # Content analysis
        if 'wordpress' in content or 'wp-content' in content:
            technologies.append('WordPress')
        elif 'joomla' in content:
            technologies.append('Joomla')
        elif 'drupal' in content:
            technologies.append('Drupal')
        
        # JavaScript frameworks
        if 'jquery' in content:
            technologies.append('jQuery')
        if 'angular' in content:
            technologies.append('AngularJS')
        if 'react' in content:
            technologies.append('React')
        if 'vue' in content:
            technologies.append('Vue.js')
        
        return technologies
    
    def _check_security_headers(self, headers: Dict) -> Dict:
        """Check for security headers."""
        security_headers = {
            'strict-transport-security': headers.get('strict-transport-security'),
            'x-frame-options': headers.get('x-frame-options'),
            'x-content-type-options': headers.get('x-content-type-options'),
            'x-xss-protection': headers.get('x-xss-protection'),
            'content-security-policy': headers.get('content-security-policy'),
            'referrer-policy': headers.get('referrer-policy')
        }
        
        return {k: v for k, v in security_headers.items() if v is not None}
    
    def directory_bruteforce(self, base_url: str, wordlist: List[str] = None) -> List[Dict]:
        """
        Perform directory brute force attack.
        
        Args:
            base_url: Base URL to scan
            wordlist: Custom wordlist (uses default if None)
            
        Returns:
            List of discovered directories/files
        """
        if wordlist is None:
            wordlist = self.common_dirs + self.common_files
        
        discovered = []
        base_url = base_url.rstrip('/')
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_path = {executor.submit(self._check_path, base_url, path): path 
                             for path in wordlist}
            
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        discovered.append(result)
                except Exception:
                    continue
        
        return discovered
    
    def _check_path(self, base_url: str, path: str) -> Optional[Dict]:
        """Check if a path exists on the server."""
        try:
            url = f"{base_url}/{path}"
            response = self.session.head(url, timeout=self.timeout, 
                                       allow_redirects=False, verify=False)
            
            if response.status_code in [200, 301, 302, 403]:
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': response.headers.get('content-length', 'Unknown'),
                    'content_type': response.headers.get('content-type', 'Unknown')
                }
        except Exception:
            pass
        
        return None
    
    def test_xss_vulnerability(self, url: str, forms: List[Dict] = None) -> List[Dict]:
        """
        Test for XSS vulnerabilities.
        
        Args:
            url: Target URL
            forms: List of forms to test (if None, will find forms)
            
        Returns:
            List of potential XSS vulnerabilities
        """
        vulnerabilities = []
        
        if forms is None:
            # Get forms from the page
            page_info = self.analyze_url(url)
            forms = page_info.get('forms', [])
        
        for form in forms:
            for payload in self.xss_payloads:
                vuln = self._test_form_xss(url, form, payload)
                if vuln:
                    vulnerabilities.append(vuln)
        
        # Test URL parameters for reflected XSS
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                vuln = self._test_parameter_xss(url, param)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_form_xss(self, url: str, form: Dict, payload: str) -> Optional[Dict]:
        """Test form for XSS vulnerability."""
        try:
            form_url = urllib.parse.urljoin(url, form['action'])
            data = {}
            
            # Fill form with payload
            for input_field in form['inputs']:
                field_name = input_field.get('name', '')
                if field_name and input_field.get('type') != 'submit':
                    data[field_name] = payload
            
            if form['method'].lower() == 'post':
                response = self.session.post(form_url, data=data, timeout=self.timeout, verify=False)
            else:
                response = self.session.get(form_url, params=data, timeout=self.timeout, verify=False)
            
            # Check if payload is reflected in response
            if payload in response.text:
                return {
                    'type': 'XSS',
                    'url': form_url,
                    'method': form['method'],
                    'payload': payload,
                    'vulnerable_parameter': list(data.keys()),
                    'confidence': 'High' if '<script>' in payload else 'Medium'
                }
        except Exception:
            pass
        
        return None
    
    def _test_parameter_xss(self, url: str, param: str) -> Optional[Dict]:
        """Test URL parameter for XSS."""
        try:
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            for payload in self.xss_payloads[:3]:  # Test with first 3 payloads
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))
                
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                if payload in response.text:
                    return {
                        'type': 'Reflected XSS',
                        'url': test_url,
                        'method': 'GET',
                        'payload': payload,
                        'vulnerable_parameter': param,
                        'confidence': 'High'
                    }
        except Exception:
            pass
        
        return None
    
    def test_sql_injection(self, url: str, forms: List[Dict] = None) -> List[Dict]:
        """
        Test for SQL injection vulnerabilities.
        
        Args:
            url: Target URL
            forms: List of forms to test
            
        Returns:
            List of potential SQL injection vulnerabilities
        """
        vulnerabilities = []
        
        if forms is None:
            page_info = self.analyze_url(url)
            forms = page_info.get('forms', [])
        
        for form in forms:
            for payload in self.sqli_payloads:
                vuln = self._test_form_sqli(url, form, payload)
                if vuln:
                    vulnerabilities.append(vuln)
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                vuln = self._test_parameter_sqli(url, param)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_form_sqli(self, url: str, form: Dict, payload: str) -> Optional[Dict]:
        """Test form for SQL injection."""
        try:
            form_url = urllib.parse.urljoin(url, form['action'])
            data = {}
            
            # Fill form with payload
            for input_field in form['inputs']:
                field_name = input_field.get('name', '')
                if field_name and input_field.get('type') != 'submit':
                    data[field_name] = payload
            
            if form['method'].lower() == 'post':
                response = self.session.post(form_url, data=data, timeout=self.timeout, verify=False)
            else:
                response = self.session.get(form_url, params=data, timeout=self.timeout, verify=False)
            
            # Check for SQL error indicators
            sql_errors = [
                'mysql_fetch_array', 'mysql_num_rows', 'mysql_error',
                'ora-01756', 'postgresql error', 'sqlite3.error',
                'microsoft ole db provider', 'unclosed quotation mark',
                'syntax error', 'mysql_connect', 'ora-00933'
            ]
            
            response_lower = response.text.lower()
            for error in sql_errors:
                if error in response_lower:
                    return {
                        'type': 'SQL Injection',
                        'url': form_url,
                        'method': form['method'],
                        'payload': payload,
                        'vulnerable_parameter': list(data.keys()),
                        'error_found': error,
                        'confidence': 'High'
                    }
        except Exception:
            pass
        
        return None
    
    def _test_parameter_sqli(self, url: str, param: str) -> Optional[Dict]:
        """Test URL parameter for SQL injection."""
        try:
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            
            for payload in self.sqli_payloads[:3]:
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, new_query, parsed_url.fragment
                ))
                
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                # Check for SQL errors
                sql_errors = ['mysql_fetch_array', 'mysql_error', 'ora-01756', 'syntax error']
                response_lower = response.text.lower()
                
                for error in sql_errors:
                    if error in response_lower:
                        return {
                            'type': 'SQL Injection',
                            'url': test_url,
                            'method': 'GET',
                            'payload': payload,
                            'vulnerable_parameter': param,
                            'error_found': error,
                            'confidence': 'High'
                        }
        except Exception:
            pass
        
        return None
    
    def check_robots_txt(self, base_url: str) -> Dict:
        """Check robots.txt file."""
        try:
            robots_url = urllib.parse.urljoin(base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                disallowed_paths = []
                sitemaps = []
                
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            disallowed_paths.append(path)
                    elif line.lower().startswith('sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        sitemaps.append(sitemap)
                
                return {
                    'found': True,
                    'url': robots_url,
                    'disallowed_paths': disallowed_paths,
                    'sitemaps': sitemaps,
                    'content': response.text
                }
        except Exception:
            pass
        
        return {'found': False}
    
    def check_sitemap(self, base_url: str) -> Dict:
        """Check sitemap.xml file."""
        try:
            sitemap_url = urllib.parse.urljoin(base_url, '/sitemap.xml')
            response = self.session.get(sitemap_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                urls = []
                
                # Parse XML to extract URLs
                if 'xml' in response.headers.get('content-type', ''):
                    soup = BeautifulSoup(response.text, 'xml')
                    for loc in soup.find_all('loc'):
                        if loc.text:
                            urls.append(loc.text)
                
                return {
                    'found': True,
                    'url': sitemap_url,
                    'urls': urls[:50],  # Limit to 50 URLs
                    'total_urls': len(urls)
                }
        except Exception:
            pass
        
        return {'found': False}
    
    def check_common_files(self, base_url: str) -> List[Dict]:
        """Check for common sensitive files."""
        sensitive_files = [
            '.env', '.git/HEAD', '.svn/entries', 'web.config',
            'php.ini', 'phpinfo.php', 'info.php', 'test.php',
            'backup.sql', 'dump.sql', 'database.yml', 'config.php',
            'wp-config.php', 'settings.py', 'local_settings.py'
        ]
        
        found_files = []
        base_url = base_url.rstrip('/')
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_file = {executor.submit(self._check_sensitive_file, base_url, file): file 
                             for file in sensitive_files}
            
            for future in as_completed(future_to_file):
                file = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        found_files.append(result)
                except Exception:
                    continue
        
        return found_files
    
    def _check_sensitive_file(self, base_url: str, filename: str) -> Optional[Dict]:
        """Check if a sensitive file exists."""
        try:
            url = f"{base_url}/{filename}"
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                return {
                    'url': url,
                    'file': filename,
                    'size': len(response.content),
                    'content_type': response.headers.get('content-type', 'Unknown'),
                    'risk_level': self._assess_file_risk(filename)
                }
        except Exception:
            pass
        
        return None
    
    def _assess_file_risk(self, filename: str) -> str:
        """Assess risk level of found file."""
        high_risk = ['.env', 'wp-config.php', 'database.yml', 'config.php', 
                    'backup.sql', 'dump.sql']
        medium_risk = ['phpinfo.php', 'info.php', '.git/HEAD', 'web.config']
        
        if filename in high_risk:
            return 'High'
        elif filename in medium_risk:
            return 'Medium'
        else:
            return 'Low'
    
    def comprehensive_scan(self, url: str) -> Dict:
        """
        Perform comprehensive web application scan.
        
        Args:
            url: Target URL
            
        Returns:
            Complete scan results
        """
        results = {
            'target': url,
            'scan_time': time.time(),
            'basic_info': {},
            'directories': [],
            'sensitive_files': [],
            'vulnerabilities': [],
            'robots_txt': {},
            'sitemap': {}
        }
        
        try:
            # Basic analysis
            results['basic_info'] = self.analyze_url(url)
            
            # Directory brute force
            results['directories'] = self.directory_bruteforce(url)
            
            # Check for sensitive files
            results['sensitive_files'] = self.check_common_files(url)
            
            # Vulnerability testing
            forms = results['basic_info'].get('forms', [])
            xss_vulns = self.test_xss_vulnerability(url, forms)
            sqli_vulns = self.test_sql_injection(url, forms)
            results['vulnerabilities'] = xss_vulns + sqli_vulns
            
            # Check robots.txt and sitemap
            results['robots_txt'] = self.check_robots_txt(url)
            results['sitemap'] = self.check_sitemap(url)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results