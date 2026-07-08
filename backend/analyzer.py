import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import time
import json
from datetime import datetime
from groq import Groq
import os
from dotenv import load_dotenv

load_dotenv()


class WebsiteAnalyzer:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc
        self.base_url = f"{urlparse(url).scheme}://{self.domain}"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.client = Groq(api_key=os.environ.get('GROQ_API_KEY'))
        
    def _fetch_page(self, url, timeout=10):
        try:
            response = self.session.get(url, timeout=timeout, verify=False)
            return response
        except Exception as e:
            return None
    
    def analyze(self):
        results = {
            'url': self.url,
            'analyzed_at': datetime.now().isoformat(),
            'summary': {},
            'security_issues': [],
            'ui_issues': [],
            'performance_issues': [],
            'recommendations': []
        }
        
        response = self._fetch_page(self.url)
        if not response:
            results['error'] = 'Could not fetch the website'
            return results
        
        soup = BeautifulSoup(response.text, 'html.parser')
        html_content = response.text
        
        # Security Analysis
        results['security_issues'] = self._analyze_security(response, soup, html_content)
        
        # UI Analysis
        results['ui_issues'] = self._analyze_ui(soup, html_content, response)
        
        # Performance Analysis
        results['performance_issues'] = self._analyze_performance(response, soup, html_content)
        
        # AI Analysis
        ai_analysis = self._ai_analysis(results, soup, html_content)
        results['ai_insights'] = ai_analysis
        results['recommendations'] = self._generate_recommendations(results)
        
        s_count = len(results['security_issues'])
        u_count = len(results['ui_issues'])
        p_count = len(results['performance_issues'])
        total = s_count + u_count + p_count
        
        s_score = max(0, 100 - s_count * 10)
        u_score = max(0, 100 - u_count * 8)
        p_score = max(0, 100 - p_count * 8)
        
        results['summary'] = {
            'security_count': s_count,
            'ui_count': u_count,
            'performance_count': p_count,
            'total_issues': total,
            'severity': self._calculate_severity(results),
            'security_score': s_score,
            'ui_score': u_score,
            'performance_score': p_score,
            'overall_score': round((s_score + u_score + p_score) / 3)
        }
        
        return results
    
    def _analyze_security(self, response, soup, html_content):
        issues = []
        headers = response.headers
        
        if not self.url.startswith('https://'):
            issues.append({
                'type': 'Transport Security',
                'severity': 'high',
                'title': 'No HTTPS',
                'description': 'Website is not using HTTPS. All data transmitted between user and server is unencrypted and vulnerable to interception.',
                'fix': 'Install an SSL/TLS certificate and configure server to redirect HTTP to HTTPS. Use Let\'s Encrypt for free certificates.'
            })
        else:
            issues.extend(self._check_https_details(response, headers))
        
        security_headers = {
            'Strict-Transport-Security': ('HSTS Missing', 'HSTS header missing. Without HSTS, users may access site over HTTP on first visit or when clearing HSTS.', 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains'),
            'X-Content-Type-Options': ('X-Content-Type-Options Missing', 'Missing X-Content-Type-Options header. Browser may MIME-sniff content leading to XSS.', 'Add X-Content-Type-Options: nosniff'),
            'X-Frame-Options': ('Clickjacking Risk', 'X-Frame-Options header missing. Site can be embedded in iframes enabling clickjacking attacks.', 'Add X-Frame-Options: DENY or SAMEORIGIN'),
            'Content-Security-Policy': ('CSP Missing', 'Content-Security-Policy header missing. No protection against XSS, code injection, or data exfiltration.', 'Add CSP header restricting script-src, style-src, img-src, and other directives'),
            'X-XSS-Protection': ('XSS Protection Missing', 'X-XSS-Protection header missing. Legacy XSS filter not enabled.', 'Add X-XSS-Protection: 1; mode=block'),
            'Referrer-Policy': ('Referrer Policy Missing', 'Referrer-Policy header missing. Full URL may leak to third parties.', 'Add Referrer-Policy: strict-origin-when-cross-origin'),
            'Permissions-Policy': ('Permissions Policy Missing', 'Permissions-Policy header missing. Browser features not restricted.', 'Add Permissions-Policy to restrict geolocation, camera, microphone, etc.'),
            'Cross-Origin-Opener-Policy': ('COOP Missing', 'Cross-Origin-Opener-Policy header missing. Cross-origin isolation not enabled.', 'Add Cross-Origin-Opener-Policy: same-origin'),
            'Cross-Origin-Embedder-Policy': ('COEP Missing', 'Cross-Origin-Embedder-Policy header missing. Cross-origin isolation not enabled.', 'Add Cross-Origin-Embedder-Policy: require-corp')
        }
        
        for header, (title, desc, fix) in security_headers.items():
            if header not in headers:
                sev = 'high' if header == 'Content-Security-Policy' else 'medium'
                issues.append({
                    'type': 'Headers',
                    'severity': sev,
                    'title': title,
                    'description': desc,
                    'fix': fix
                })
        
        issues.extend(self._check_cookie_security(response))
        issues.extend(self._check_inline_event_handlers(soup))
        issues.extend(self._check_dangerous_js_patterns(soup, html_content))
        issues.extend(self._check_csrf_tokens(soup))
        issues.extend(self._check_directory_listing(response, soup))
        issues.extend(self._check_open_redirects(soup))
        issues.extend(self._check_cors_misconfiguration(headers))
        issues.extend(self._check_sri(soup))
        issues.extend(self._check_sensitive_file_exposure())
        issues.extend(self._check_form_security(soup))
        issues.extend(self._check_third_party_scripts(soup))
        issues.extend(self._check_password_fields(soup))
        issues.extend(self._check_clickjacking_protection(headers, soup))
        issues.extend(self._check_mime_sniffing(headers))
        issues.extend(self._check_html_comments(soup))
        issues.extend(self._check_debug_info(response, soup, html_content))
        
        return issues
    
    def _check_https_details(self, response, headers):
        issues = []
        
        if hasattr(response, 'raw') and hasattr(response.raw, 'version'):
            version = str(response.raw.version)
            if 'SSL' in version or version in ['TLS/1.0', 'TLS/1.1']:
                issues.append({
                    'type': 'Transport Security',
                    'severity': 'high',
                    'title': 'Outdated TLS/SSL Version',
                    'description': f'Server uses {version}. Modern TLS 1.2+ is required for security.',
                    'fix': 'Disable TLS 1.0, TLS 1.1, and SSL protocols. Enable only TLS 1.2 and 1.3.'
                })
        
        hsts = headers.get('Strict-Transport-Security', '')
        if hsts and 'max-age=' in hsts:
            match = re.search(r'max-age=(\d+)', hsts)
            if match and int(match.group(1)) < 31536000:
                issues.append({
                    'type': 'Headers',
                    'severity': 'medium',
                    'title': 'HSTS max-age Too Short',
                    'description': f'HSTS max-age is {match.group(1)} seconds. Should be at least 31536000 (1 year).',
                    'fix': 'Increase HSTS max-age to at least 31536000 seconds'
                })
        
        return issues
    
    def _check_cookie_security(self, response):
        issues = []
        cookies = response.cookies
        
        for cookie in cookies:
            flags = []
            if not cookie.secure:
                flags.append('Secure')
            if not getattr(cookie, 'httponly', False):
                flags.append('HttpOnly')
            if not getattr(cookie, 'samesite', None):
                flags.append('SameSite')
            
            if flags:
                issues.append({
                    'type': 'Cookie Security',
                    'severity': 'medium',
                    'title': f'Insecure Cookie: {cookie.name}',
                    'description': f'Cookie "{cookie.name}" missing security flags: {", ".join(flags)}. Exposes cookie to XSS and MITM attacks.',
                    'fix': f'Set Secure, HttpOnly, and SameSite=Strict/Lax flags for cookie "{cookie.name}"'
                })
        
        return issues
    
    def _check_inline_event_handlers(self, soup):
        issues = []
        event_handlers = ['onclick', 'onerror', 'onload', 'onmouseover', 'onmouseout', 'onmousedown', 'onmouseup',
                         'onchange', 'onsubmit', 'onfocus', 'onblur', 'onkeydown', 'onkeypress', 'onkeyup',
                         'ondblclick', 'oncontextmenu', 'onwheel', 'ontouchstart', 'ontouchend', 'ontouchmove']
        
        found_handlers = []
        for tag in soup.find_all(True):
            for handler in event_handlers:
                if tag.get(handler):
                    found_handlers.append(f'{tag.name}.{handler}')
        
        if found_handlers:
            issues.append({
                'type': 'XSS',
                'severity': 'medium',
                'title': 'Inline Event Handlers Detected',
                'description': f'Found {len(found_handlers)} inline event handlers (e.g., onclick, onerror). These are XSS attack vectors.',
                'fix': 'Remove inline event handlers and attach events via external JavaScript using addEventListener'
            })
        
        return issues
    
    def _check_dangerous_js_patterns(self, soup, html_content):
        issues = []
        
        if re.search(r'\beval\s*\(', html_content) or re.search(r'new\s+Function\s*\(', html_content):
            issues.append({
                'type': 'XSS',
                'severity': 'high',
                'title': 'Dangerous eval() or Function() Usage',
                'description': 'JavaScript uses eval() or new Function(). This allows arbitrary code execution and is a critical XSS vector.',
                'fix': 'Replace eval() and Function() with safer alternatives. Parse JSON with JSON.parse() instead.'
            })
        
        if re.search(r'document\.write\s*\(', html_content):
            issues.append({
                'type': 'Security',
                'severity': 'medium',
                'title': 'document.write() Usage Detected',
                'description': 'document.write() can overwrite the entire document and is deprecated. Can be exploited for XSS.',
                'fix': 'Replace document.write() with modern DOM manipulation methods (createElement, appendChild, etc.)'
            })
        
        if re.search(r'set(Timeout|Interval)\s*\(\s*["\']', html_content):
            issues.append({
                'type': 'XSS',
                'severity': 'medium',
                'title': 'setTimeout/setInterval With String Argument',
                'description': 'setTimeout/setInterval called with string argument behaves like eval(). XSS risk.',
                'fix': 'Pass function references instead of strings to setTimeout/setInterval'
            })
        
        dangerous_patterns = 0
        for script in soup.find_all('script'):
            if script.string and ('innerHTML' in script.string or 'outerHTML' in script.string):
                dangerous_patterns += 1
        
        if dangerous_patterns > 0:
            issues.append({
                'type': 'XSS',
                'severity': 'medium',
                'title': 'innerHTML/outerHTML Usage',
                'description': f'Found {dangerous_patterns} script(s) using innerHTML or outerHTML. Can lead to XSS if user input is inserted.',
                'fix': 'Use textContent or createElement/setAttribute instead of innerHTML for dynamic content'
            })
        
        return issues
    
    def _check_csrf_tokens(self, soup):
        issues = []
        forms = soup.find_all('form')
        
        for form in forms:
            has_csrf = bool(form.find('input', attrs={'name': re.compile(r'csrf|token|nonce|authenticity', re.I)}))
            method = form.get('method', 'get').lower()
            
            if method == 'post' and not has_csrf:
                issues.append({
                    'type': 'CSRF',
                    'severity': 'high',
                    'title': 'CSRF Token Missing',
                    'description': f'Form with action="{form.get("action", "")}" uses POST method but has no CSRF protection token.',
                    'fix': 'Add CSRF token to all state-changing forms. Use framework-provided CSRF protection or synchronizer token pattern.'
                })
        
        return issues
    
    def _check_directory_listing(self, response, soup):
        issues = []
        
        if 'Index of /' in response.text or 'Directory listing for /' in response.text:
            issues.append({
                'type': 'Information Disclosure',
                'severity': 'high',
                'title': 'Directory Listing Enabled',
                'description': 'Server allows directory listing. Attackers can view all files in directories.',
                'fix': 'Disable directory listing in web server configuration (Options -Indexes in Apache, autoindex off in Nginx)'
            })
        
        return issues
    
    def _check_open_redirects(self, soup):
        issues = []
        
        links = soup.find_all('a', href=True)
        redirect_params = ['url', 'redirect', 'redirect_to', 'return', 'next', 'goto', 'link', 'target', 'dest', 'destination']
        
        for link in links[:30]:
            href = link['href']
            if any(param in href.lower() for param in redirect_params):
                if 'http' in href.lower() and self.domain not in href:
                    issues.append({
                        'type': 'Open Redirect',
                        'severity': 'medium',
                        'title': 'Potential Open Redirect',
                        'description': f'Link contains redirect parameter: {href[:100]}...',
                        'fix': 'Validate redirect URLs against a whitelist. Ensure redirects only point to same domain or expected destinations.'
                    })
                    break
        
        return issues
    
    def _check_cors_misconfiguration(self, headers):
        issues = []
        
        acao = headers.get('Access-Control-Allow-Origin', '')
        if acao == '*':
            issues.append({
                'type': 'CORS',
                'severity': 'high',
                'title': 'Overly Permissive CORS',
                'description': 'Access-Control-Allow-Origin is set to wildcard (*). Any origin can access resources.',
                'fix': 'Restrict CORS to specific trusted origins. Never use wildcard with credentials.'
            })
        
        acac = headers.get('Access-Control-Allow-Credentials', '')
        if acac == 'true' and acao == '*':
            issues.append({
                'type': 'CORS',
                'severity': 'critical',
                'title': 'Wildcard CORS With Credentials',
                'description': 'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true. Critical security misconfiguration.',
                'fix': 'Remove wildcard origin or disable credentials. Specify exact trusted origins.'
            })
        
        return issues
    
    def _check_sri(self, soup):
        issues = []
        
        scripts = soup.find_all('script', src=True)
        for script in scripts[:10]:
            if not script.get('integrity'):
                src = script.get('src', '')
                if any(domain in src for domain in ['cdn', 'cloudflare', 'googleapis', 'bootstrapcdn', 'unpkg', 'jsdelivr', 'cdnjs']):
                    issues.append({
                        'type': 'Supply Chain',
                        'severity': 'medium',
                        'title': 'Missing Subresource Integrity',
                        'description': f'External script from CDN lacks integrity attribute: {src[:80]}...',
                        'fix': 'Add integrity attribute with SHA256/SHA384/SHA512 hash to all CDN-sourced scripts and stylesheets.'
                    })
                    break
        
        return issues
    
    def _check_sensitive_file_exposure(self):
        issues = []
        
        sensitive_files = {
            '/.git/config': 'critical',
            '/.git/HEAD': 'critical', 
            '/.env': 'critical',
            '/.env.local': 'critical',
            '/wp-config.php': 'critical',
            '/.DS_Store': 'high',
            '/.svn/entries': 'high',
            '/web.config': 'medium',
            '/.htaccess': 'medium',
            '/server-status': 'high',
            '/server-info': 'high',
            '/.user.ini': 'medium',
            '/.idea/workspace.xml': 'medium',
            '/composer.json': 'low',
            '/package.json': 'low',
            '/.npmrc': 'high',
            '/.yarnrc': 'medium',
            '/Gemfile': 'low',
            '/Pipfile': 'low',
            '/go.mod': 'low',
            '/Cargo.toml': 'low',
            '/yarn.lock': 'low',
            '/package-lock.json': 'low',
            '/bower.json': 'low'
        }
        
        for file_path, severity in sensitive_files.items():
            test_url = urljoin(self.base_url, file_path)
            try:
                resp = self.session.get(test_url, timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    content_preview = resp.text[:200] if resp.text else ''
                    issues.append({
                        'type': 'Sensitive Files',
                        'severity': severity,
                        'title': f'Exposed: {file_path}',
                        'description': f'Sensitive file accessible at {file_path}. Content preview: {content_preview[:100]}...',
                        'fix': f'Restrict access to {file_path}. Use server configuration to deny access or move sensitive files outside web root.'
                    })
            except:
                pass
        
        return issues
    
    def _check_form_security(self, soup):
        issues = []
        
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            if method == 'get' and any(sensitive in action.lower() for sensitive in ['login', 'signin', 'auth', 'password', 'login']):
                issues.append({
                    'type': 'Form Security',
                    'severity': 'medium',
                    'title': 'Sensitive Form Using GET Method',
                    'description': f'Login/auth form uses GET method. Credentials appear in URL and server logs.',
                    'fix': 'Change form method to POST for all sensitive operations like login and password changes.'
                })
            
            inputs = form.find_all('input', type='password')
            for inp in inputs:
                autocomplete = inp.get('autocomplete', '')
                if autocomplete not in ['off', 'new-password', 'current-password']:
                    issues.append({
                        'type': 'Form Security',
                        'severity': 'low',
                        'title': 'Password Field Autocomplete',
                        'description': 'Password input does not have autocomplete="new-password" or autocomplete="current-password". Browser may store credentials.',
                        'fix': 'Add autocomplete="current-password" for login, autocomplete="new-password" for registration.'
                    })
                    break
        
        return issues
    
    def _check_third_party_scripts(self, soup):
        issues = []
        
        scripts = soup.find_all('script', src=True)
        third_party_domains = set()
        trusted_domains = {'self', 'googleapis.com', 'gstatic.com', 'jquery.com', 'bootstrapcdn.com', 'cloudflare.com'}
        
        for script in scripts:
            src = script.get('src', '')
            if src:
                try:
                    domain = urlparse(src).netloc
                    if domain and domain not in trusted_domains:
                        third_party_domains.add(domain)
                except:
                    pass
        
        if len(third_party_domains) > 5:
            issues.append({
                'type': 'Supply Chain',
                'severity': 'medium',
                'title': 'Excessive Third-Party Scripts',
                'description': f'Found {len(third_party_domains)} third-party script domains: {", ".join(list(third_party_domains)[:5])}...',
                'fix': 'Audit third-party scripts. Remove unnecessary ones. Use Subresource Integrity and consider self-hosting critical scripts.'
            })
        
        return issues
    
    def _check_password_fields(self, soup):
        issues = []
        
        password_inputs = soup.find_all('input', type='password')
        for inp in password_inputs:
            if not inp.get('autocomplete'):
                issues.append({
                    'type': 'Form Security',
                    'severity': 'low',
                    'title': 'Password Field Missing Autocomplete',
                    'description': 'Password input lacks autocomplete attribute.',
                    'fix': 'Add autocomplete="current-password" for login forms, autocomplete="new-password" for registration.'
                })
                break
        
        return issues
    
    def _check_clickjacking_protection(self, headers, soup):
        issues = []
        
        xfo = headers.get('X-Frame-Options', '').upper()
        csp = headers.get('Content-Security-Policy', '')
        
        if xfo not in ['DENY', 'SAMEORIGIN'] and 'frame-ancestors' not in csp.lower():
            issues.append({
                'type': 'Clickjacking',
                'severity': 'high',
                'title': 'No Clickjacking Protection',
                'description': 'Site can be embedded in iframes. Attackers can trick users into clicking hidden elements.',
                'fix': 'Add X-Frame-Options: DENY header or CSP frame-ancestors directive'
            })
        
        return issues
    
    def _check_mime_sniffing(self, headers):
        issues = []
        
        if headers.get('X-Content-Type-Options', '').lower() != 'nosniff':
            issues.append({
                'type': 'MIME Sniffing',
                'severity': 'medium',
                'title': 'MIME Sniffing Not Prevented',
                'description': 'X-Content-Type-Options header missing or not set to nosniff. Browser may override declared content types.',
                'fix': 'Add X-Content-Type-Options: nosniff header'
            })
        
        return issues
    
    def _check_html_comments(self, soup):
        issues = []
        
        comments = soup.find_all(string=lambda text: isinstance(text, type(soup.new_string(''))))
        sensitive_in_comments = False
        for comment in comments:
            if any(keyword in str(comment).lower() for keyword in ['password', 'secret', 'api_key', 'token', 'database', 'admin', 'config']):
                sensitive_in_comments = True
                break
        
        if sensitive_in_comments:
            issues.append({
                'type': 'Information Disclosure',
                'severity': 'high',
                'title': 'Sensitive Data in HTML Comments',
                'description': 'HTML comments may contain sensitive information like credentials or internal paths.',
                'fix': 'Remove all sensitive data from HTML comments before deployment. Use build processes to strip comments.'
            })
        
        return issues
    
    def _check_debug_info(self, response, soup, html_content):
        issues = []
        
        debug_indicators = ['debug=true', 'debug=1', 'debug_mode', 'stack trace', 'traceback', 'error_reporting', 'display_errors', 'show_errors']
        debug_found = any(indicator in html_content.lower() for indicator in debug_indicators)
        
        if debug_found:
            issues.append({
                'type': 'Information Disclosure',
                'severity': 'high',
                'title': 'Debug Information Exposed',
                'description': 'Page contains debug information, stack traces, or error reporting enabled. Reveals internal implementation details.',
                'fix': 'Disable debug mode in production. Configure error reporting to hide detailed errors from users.'
            })
        
        issues.extend(self._check_sql_injection_patterns(soup, html_content))
        issues.extend(self._check_xxe_patterns(soup, html_content))
        issues.extend(self._check_ssrf_patterns(soup))
        issues.extend(self._check_outdated_libraries(soup))
        
        return issues
    
    def _check_sql_injection_patterns(self, soup, html_content):
        issues = []
        
        sql_patterns = [
            r"SELECT\s+.*\s+FROM",
            r"INSERT\s+INTO",
            r"UPDATE\s+.*\s+SET",
            r"DELETE\s+FROM",
            r"DROP\s+TABLE",
            r"UNION\s+SELECT",
            r"OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"AND\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"1\s*=\s*1",
            r"admin'\s*--"
        ]
        
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for inp in inputs:
                if inp.get('type') in ['text', 'search', 'email', 'url']:
                    name = inp.get('name', '').lower()
                    if any(keyword in name for keyword in ['user', 'email', 'search', 'query', 'id', 'name']):
                        for pattern in sql_patterns[:4]:
                            if re.search(pattern, html_content, re.IGNORECASE):
                                issues.append({
                                    'type': 'Injection',
                                    'severity': 'high',
                                    'title': 'Potential SQL Injection Point',
                                    'description': f'Input field "{name}" may be vulnerable to SQL injection. Dangerous SQL patterns found in page source.',
                                    'fix': 'Use parameterized queries/prepared statements. Validate and sanitize all user inputs. Use ORM frameworks.'
                                })
                                return issues
        
        return issues
    
    def _check_xxe_patterns(self, soup, html_content):
        issues = []
        
        xxe_indicators = ['xml version', 'DOCTYPE', 'ENTITY', 'SYSTEM', 'PUBLIC']
        forms_with_file = soup.find_all('input', type='file')
        
        if forms_with_file and any(indicator in html_content for indicator in xxe_indicators):
            issues.append({
                'type': 'Injection',
                'severity': 'high',
                'title': 'Potential XXE Vulnerability',
                'description': 'File upload forms detected with XML processing indicators. May be vulnerable to XML External Entity attacks.',
                'fix': 'Disable external entity processing in XML parsers. Use JSON instead of XML where possible. Validate uploaded files.'
            })
        
        return issues
    
    def _check_ssrf_patterns(self, soup):
        issues = []
        
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for inp in inputs:
                name = inp.get('name', '').lower()
                if any(keyword in name for keyword in ['url', 'link', 'redirect', 'callback', 'webhook', 'fetch']):
                    issues.append({
                        'type': 'SSRF',
                        'severity': 'medium',
                        'title': 'Potential SSRF Vector',
                        'description': f'Input field "{inp.get("name")}" accepts URLs. May be vulnerable to Server-Side Request Forgery.',
                        'fix': 'Validate and whitelist allowed URL schemes and domains. Disable private IP ranges. Use allowlists for redirect targets.'
                    })
                    return issues
        
        return issues
    
    def _check_outdated_libraries(self, soup):
        issues = []
        
        scripts = soup.find_all('script', src=True)
        outdated_versions = {
            'jquery': ['1.6', '1.7', '1.8', '1.9', '1.10', '1.11', '1.12', '2.0', '2.1', '2.2'],
            'bootstrap': ['2.', '3.0', '3.1', '3.2', '3.3'],
            'angular': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6'],
            'react': ['0.14', '15', '16.0', '16.1', '16.2', '16.3', '16.4', '16.5', '16.6', '16.7', '16.8'],
            'vue': ['1.', '2.0', '2.1', '2.2', '2.3', '2.4', '2.5', '2.6']
        }
        
        for script in scripts:
            src = script.get('src', '').lower()
            for lib, versions in outdated_versions.items():
                if lib in src:
                    for version in versions:
                        if version in src:
                            issues.append({
                                'type': 'Supply Chain',
                                'severity': 'medium',
                                'title': f'Outdated {lib.title()} Library',
                                'description': f'Page uses {lib.title()} version containing "{version}". This version may have known security vulnerabilities.',
                                'fix': f'Update {lib.title()} to the latest stable version. Check CVE databases for specific vulnerabilities in this version.'
                            })
                            return issues
        
        return issues
    
    def _analyze_ui(self, soup, html_content, response):
        issues = []
        
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        if not viewport:
            issues.append({
                'type': 'Responsive',
                'severity': 'high',
                'title': 'No Viewport Meta Tag',
                'description': 'Page is not optimized for mobile devices. Content will not scale properly.',
                'fix': 'Add <meta name="viewport" content="width=device-width, initial-scale=1.0">'
            })
        else:
            content = viewport.get('content', '')
            if 'user-scalable=no' in content or 'maximum-scale=1' in content:
                issues.append({
                    'type': 'Accessibility',
                    'severity': 'medium',
                    'title': 'Viewport Prevents Zooming',
                    'description': 'Viewport meta tag prevents user scaling. Violates WCAG accessibility guidelines.',
                    'fix': 'Remove user-scalable=no and maximum-scale=1. Allow users to zoom up to 5x.'
                })
        
        images = soup.find_all('img')
        missing_alt = sum(1 for img in images if not img.get('alt'))
        if missing_alt > 0:
            issues.append({
                'type': 'Accessibility',
                'severity': 'high',
                'title': 'Missing Alt Attributes',
                'description': f'{missing_alt} images missing alt attributes. Screen readers cannot describe them.',
                'fix': 'Add descriptive alt text to all meaningful images. Use alt="" for decorative images.'
            })
        
        title = soup.find('title')
        if not title or not title.text.strip():
            issues.append({
                'type': 'SEO',
                'severity': 'medium',
                'title': 'Missing Title Tag',
                'description': 'Page does not have a title tag. Critical for SEO and browser tabs.',
                'fix': 'Add a descriptive <title> tag (50-60 characters)'
            })
        elif len(title.text.strip()) > 70:
            issues.append({
                'type': 'SEO',
                'severity': 'low',
                'title': 'Title Too Long',
                'description': f'Title is {len(title.text.strip())} characters. Recommended 50-60 characters for SEO.',
                'fix': 'Shorten title tag to 50-60 characters'
            })
        
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if not meta_desc:
            issues.append({
                'type': 'SEO',
                'severity': 'low',
                'title': 'Missing Meta Description',
                'description': 'Page does not have a meta description. Search results will show auto-generated snippets.',
                'fix': 'Add meta description (150-160 characters) summarizing page content'
            })
        
        h1_tags = soup.find_all('h1')
        if len(h1_tags) == 0:
            issues.append({
                'type': 'SEO',
                'severity': 'medium',
                'title': 'No H1 Tag',
                'description': 'Page does not have an H1 heading. Search engines use H1 to understand page topic.',
                'fix': 'Add exactly one H1 tag with the main page title'
            })
        elif len(h1_tags) > 1:
            issues.append({
                'type': 'SEO',
                'severity': 'low',
                'title': 'Multiple H1 Tags',
                'description': f'Found {len(h1_tags)} H1 tags. Use only one H1 per page for proper hierarchy.',
                'fix': 'Use only one H1 tag per page. Use H2-H6 for subsections.'
            })
        
        headings = []
        for i in range(1, 7):
            headings.extend([(i, h.get_text(strip=True)) for h in soup.find_all(f'h{i}')])
        
        if headings:
            for idx in range(len(headings) - 1):
                curr_level = headings[idx][0]
                next_level = headings[idx + 1][0]
                if next_level > curr_level + 1:
                    issues.append({
                        'type': 'Accessibility',
                        'severity': 'medium',
                        'title': 'Heading Hierarchy Gap',
                        'description': f'Heading level jumps from H{curr_level} to H{next_level}. Screen readers may miss content.',
                        'fix': 'Maintain sequential heading hierarchy (H1 -> H2 -> H3). Do not skip levels.'
                    })
                    break
        
        html_tag = soup.find('html')
        if html_tag and not html_tag.get('lang'):
            issues.append({
                'type': 'Accessibility',
                'severity': 'medium',
                'title': 'Missing Language Attribute',
                'description': 'HTML tag missing lang attribute. Screen readers and translation tools cannot identify language.',
                'fix': 'Add lang attribute to <html> tag (e.g., <html lang="en">)'
            })
        
        charset = soup.find('meta', attrs={'charset': True}) or soup.find('meta', attrs={'http-equiv': 'Content-Type'})
        if not charset:
            issues.append({
                'type': 'SEO',
                'severity': 'medium',
                'title': 'Missing Charset Declaration',
                'description': 'Page does not declare character encoding. Can cause mojibake and encoding attacks.',
                'fix': 'Add <meta charset="UTF-8"> as first element in <head>'
            })
        
        if not soup.find('link', rel='icon') and not soup.find('link', rel='shortcut icon'):
            issues.append({
                'type': 'UI',
                'severity': 'low',
                'title': 'Missing Favicon',
                'description': 'Page does not have a favicon. Branding and bookmarking affected.',
                'fix': 'Add <link rel="icon" href="/favicon.ico"> or use SVG favicon'
            })
        
        empty_buttons = [a for a in soup.find_all('a', href=True) if not a.get_text(strip=True) and not a.find('img')]
        empty_buttons += [btn for btn in soup.find_all('button') if not btn.get_text(strip=True) and not btn.find('img')]
        if empty_buttons:
            issues.append({
                'type': 'Accessibility',
                'severity': 'medium',
                'title': 'Empty Interactive Elements',
                'description': f'Found {len(empty_buttons)} links or buttons with no accessible text. Screen readers cannot interpret them.',
                'fix': 'Add descriptive text to all links and buttons, or add aria-label'
            })
        
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                inp_type = inp.get('type', '').lower()
                if inp_type in ['text', 'email', 'password', 'search', 'tel', 'url', 'textarea', 'select-one', 'select-multiple']:
                    has_label = bool(form.find('label', attrs={'for': inp.get('id')}))
                    has_aria = bool(inp.get('aria-label') or inp.get('aria-labelledby'))
                    has_placeholder = bool(inp.get('placeholder'))
                    if not has_label and not has_aria and has_placeholder and not inp.get('id'):
                        issues.append({
                            'type': 'Accessibility',
                            'severity': 'high',
                            'title': 'Placeholder-Only Input Label',
                            'description': f'Input "{inp.get("name", "unknown")}" has placeholder but no associated label.',
                            'fix': 'Add explicit <label> element linked via for/id. Do not rely on placeholder as label.'
                        })
                        break
        
        tables = soup.find_all('table')
        for table in tables:
            if not table.find('th'):
                issues.append({
                    'type': 'Accessibility',
                    'severity': 'medium',
                    'title': 'Table Missing Headers',
                    'description': 'Data table lacks <th> header cells. Screen readers cannot associate data with headers.',
                    'fix': 'Add <th> elements for table headers and scope attributes'
                })
                break
        
        inline_styles = soup.find_all(style=True)
        if len(inline_styles) > 10:
            issues.append({
                'type': 'Maintainability',
                'severity': 'low',
                'title': 'Excessive Inline Styles',
                'description': f'Found {len(inline_styles)} elements with inline styles. Hard to maintain and override.',
                'fix': 'Move inline styles to external CSS classes'
            })
        
        links = soup.find_all('a', href=True)
        broken_links = 0
        for link in links[:15]:
            href = link['href']
            if href.startswith('/'):
                href = urljoin(self.base_url, href)
            elif not href.startswith(('http://', 'https://', 'mailto:', 'tel:', '#')):
                href = urljoin(self.url, href)
            
            try:
                resp = self.session.head(href, timeout=5, allow_redirects=True)
                if resp.status_code >= 400:
                    broken_links += 1
            except:
                broken_links += 1
        
        if broken_links > 0:
            issues.append({
                'type': 'Links',
                'severity': 'medium',
                'title': 'Broken Internal Links',
                'description': f'Found {broken_links} broken or unresponsive internal links.',
                'fix': 'Audit all links. Fix or remove broken links. Implement 404 monitoring.'
            })
        
        deprecated_tags = soup.find_all(['center', 'font', 'marquee', 'blink', 'acronym', 'applet', 'basefont', 'big', 'tt', 'strike', 'frameset', 'frame'])
        if deprecated_tags:
            issues.append({
                'type': 'Maintainability',
                'severity': 'low',
                'title': 'Deprecated HTML Tags',
                'description': f'Found {len(deprecated_tags)} deprecated HTML tags ({", ".join(set(t.name for t in deprecated_tags))}). These are not supported in HTML5.',
                'fix': 'Replace deprecated tags with modern HTML5 equivalents (e.g., <center> -> CSS flexbox/grid, <font> -> CSS)'
            })
        
        if not soup.find('a', attrs={'href': '#main'}) and not soup.find('a', attrs={'href': '#content'}):
            issues.append({
                'type': 'Accessibility',
                'severity': 'medium',
                'title': 'Missing Skip Navigation',
                'description': 'No skip-to-content link found. Keyboard users must tab through all navigation items.',
                'fix': 'Add <a href="#main" class="skip-link">Skip to main content</a> as first focusable element'
            })
        
        images_as_links = soup.find_all('a', href=True)
        image_links_missing_alt = 0
        for link in images_as_links:
            img = link.find('img')
            if img and not img.get('alt') and not link.get_text(strip=True):
                image_links_missing_alt += 1
        
        if image_links_missing_alt > 0:
            issues.append({
                'type': 'Accessibility',
                'severity': 'high',
                'title': 'Image Links Missing Alt Text',
                'description': f'{image_links_missing_alt} image links missing alt text. Screen readers cannot describe link destination.',
                'fix': 'Add descriptive alt text to all images inside links. Describe the link destination/purpose.'
            })
        
        forms = soup.find_all('form')
        forms_without_autocomplete = 0
        for form in forms:
            inputs = form.find_all('input')
            for inp in inputs:
                if inp.get('type') in ['text', 'email', 'password', 'tel', 'url', 'search']:
                    if not inp.get('autocomplete'):
                        forms_without_autocomplete += 1
                        break
        
        if forms_without_autocomplete > 0:
            issues.append({
                'type': 'Accessibility',
                'severity': 'medium',
                'title': 'Forms Missing Autocomplete',
                'description': f'{forms_without_autocomplete} form(s) missing autocomplete attributes. Browsers cannot autofill fields.',
                'fix': 'Add appropriate autocomplete attributes (name, email, tel, address-line1, etc.) to form inputs'
            })
        
        return issues
    
    def _analyze_performance(self, response, soup, html_content):
        issues = []
        
        page_size_kb = len(response.content) / 1024
        if page_size_kb > 3000:
            issues.append({
                'type': 'Performance',
                'severity': 'high',
                'title': 'Large Page Size',
                'description': f'Page size is {page_size_kb:.1f} KB ({page_size_kb/1024:.2f} MB). Recommended under 3MB for fast loading.',
                'fix': 'Compress images, minify CSS/JS, remove unused code, enable compression'
            })
        
        if response.headers.get('Content-Encoding') not in ['gzip', 'br', 'deflate']:
            issues.append({
                'type': 'Performance',
                'severity': 'high',
                'title': 'No Response Compression',
                'description': 'Response is not compressed. Transfer size is much larger than necessary.',
                'fix': 'Enable gzip or brotli compression on server. Can reduce transfer size by 60-80%.'
            })
        
        cache_control = response.headers.get('Cache-Control', '')
        if 'max-age' not in cache_control.lower():
            issues.append({
                'type': 'Performance',
                'severity': 'medium',
                'title': 'No Cache Headers',
                'description': 'Cache-Control header missing or has no max-age. Repeat visitors must re-download all resources.',
                'fix': 'Add Cache-Control: public, max-age=31536000 for static assets. Use immutable for versioned assets.'
            })
        
        if 'ETag' not in response.headers and 'Last-Modified' not in response.headers:
            issues.append({
                'type': 'Performance',
                'severity': 'low',
                'title': 'No Validator Headers',
                'description': 'Missing ETag or Last-Modified headers. Reduces caching efficiency.',
                'fix': 'Add ETag or Last-Modified headers to enable conditional requests'
            })
        
        all_elements = soup.find_all(True)
        dom_size = len(all_elements)
        if dom_size > 1500:
            issues.append({
                'type': 'Performance',
                'severity': 'high',
                'title': 'Excessive DOM Size',
                'description': f'Page has {dom_size} DOM elements. Large DOM causes slow rendering, layout, and paint.',
                'fix': 'Reduce DOM complexity. Remove unnecessary elements, paginate lists, virtualize long lists.'
            })
        
        max_depth = 0
        for tag in all_elements:
            depth = len(list(tag.parents))
            max_depth = max(max_depth, depth)
        
        if max_depth > 32:
            issues.append({
                'type': 'Performance',
                'severity': 'medium',
                'title': 'Deep DOM Nesting',
                'description': f'Maximum DOM depth is {max_depth}. Deeply nested elements slow down selector matching and layout.',
                'fix': 'Flatten DOM structure. Avoid excessive nesting.'
            })
        
        iframes = soup.find_all('iframe')
        if len(iframes) > 3:
            issues.append({
                'type': 'Performance',
                'severity': 'medium',
                'title': 'Too Many Iframes',
                'description': f'Page contains {len(iframes)} iframes. Each iframe creates a new browsing context and blocking resource.',
                'fix': 'Reduce iframe count. Lazy load iframes below the fold. Use async loading.'
            })
        
        images = soup.find_all('img')
        large_images = 0
        missing_dimensions = 0
        
        for img in images[:20]:
            src = img.get('src')
            if src:
                if src.startswith('/'):
                    src = urljoin(self.base_url, src)
                elif not src.startswith(('http://', 'https://')):
                    src = urljoin(self.url, src)
                
                try:
                    img_resp = self.session.head(src, timeout=5)
                    img_size = int(img_resp.headers.get('Content-Length', 0))
                    if img_size > 300000:
                        large_images += 1
                except:
                    pass
            
            if not img.get('width') or not img.get('height'):
                missing_dimensions += 1
        
        if large_images > 0:
            issues.append({
                'type': 'Performance',
                'severity': 'high',
                'title': 'Unoptimized Images',
                'description': f'Found {large_images} images larger than 300KB. Large images slow down page load.',
                'fix': 'Compress images, use WebP/AVIF formats, implement responsive images with srcset, lazy load below-fold images'
            })
        
        if missing_dimensions > 0 and missing_dimensions == len(images[:20]):
            issues.append({
                'type': 'Performance',
                'severity': 'medium',
                'title': 'Images Missing Dimensions',
                'description': f'{missing_dimensions} images lack width/height attributes. Causes layout shift (CLS).',
                'fix': 'Add explicit width and height attributes to all images, or use aspect-ratio CSS'
            })
        
        css_in_head = soup.find_all('link', rel='stylesheet')
        render_blocking_css = 0
        for link in css_in_head:
            if not link.get('media') or link.get('media') == 'all':
                render_blocking_css += 1
        
        if render_blocking_css > 2:
            issues.append({
                'type': 'Performance',
                'severity': 'medium',
                'title': 'Render-Blocking CSS',
                'description': f'{render_blocking_css} CSS files block rendering. Critical CSS should be inlined.',
                'fix': 'Inline critical CSS in <style> tag. Load remaining CSS asynchronously with media="print" and onload trick.'
            })
        
        js_in_head = soup.find_all('script')
        render_blocking_js = 0
        for script in js_in_head:
            if not script.get('src'):
                continue
            parent = script.parent
            if parent and parent.name == 'head':
                if not script.get('async') and not script.get('defer') and not script.get('type') == 'module':
                    render_blocking_js += 1
        
        if render_blocking_js > 0:
            issues.append({
                'type': 'Performance',
                'severity': 'medium',
                'title': 'Render-Blocking JavaScript',
                'description': f'{render_blocking_js} scripts in <head> block rendering without async/defer.',
                'fix': 'Add async or defer attribute to scripts in head. Move non-critical scripts to end of body.'
            })
        
        if not soup.find_all('link', rel='preconnect') and not soup.find_all('link', rel='dns-prefetch'):
            third_party_domains = set()
            for script in soup.find_all('script', src=True):
                try:
                    domain = urlparse(script.get('src', '')).netloc
                    if domain:
                        third_party_domains.add(domain)
                except:
                    pass
            
            if len(third_party_domains) > 2:
                issues.append({
                    'type': 'Performance',
                    'severity': 'low',
                    'title': 'Missing Resource Hints',
                    'description': 'No preconnect or dns-prefetch hints for third-party origins.',
                    'fix': 'Add <link rel="preconnect"> for critical third-party origins to reduce connection time'
                })
        
        images_without_lazy = sum(1 for img in images if not img.get('loading') == 'lazy')
        if images_without_lazy > 10:
            issues.append({
                'type': 'Performance',
                'severity': 'low',
                'title': 'Missing Lazy Loading',
                'description': f'{images_without_lazy} images could use lazy loading. Below-fold images delay initial render.',
                'fix': 'Add loading="lazy" to images below the fold. Consider native lazy loading for iframes too.'
            })
        
        if hasattr(response, 'history') and len(response.history) > 1:
            issues.append({
                'type': 'Performance',
                'severity': 'medium',
                'title': 'Redirect Chain Detected',
                'description': f'Request followed {len(response.history)} redirects. Each redirect adds round-trip latency.',
                'fix': 'Minimize redirects. Direct resources to final URL. Fix redirect chains to single 301.'
            })
        
        modern_formats = 0
        total_checked = 0
        for img in images[:10]:
            src = img.get('src', '')
            if src:
                total_checked += 1
                if any(fmt in src.lower() for fmt in ['.webp', '.avif']):
                    modern_formats += 1
        
        if total_checked > 0 and modern_formats == 0:
            issues.append({
                'type': 'Performance',
                'severity': 'low',
                'title': 'No Modern Image Formats',
                'description': f'Checked {total_checked} images. None use modern formats (WebP/AVIF).',
                'fix': 'Serve images in WebP or AVIF format with fallback to JPEG/PNG. Use <picture> element or content negotiation.'
            })
        
        sync_xhr = html_content.lower().count('xmlhttprequest')
        if sync_xhr > 0 and 'async' not in html_content.lower()[:5000]:
            issues.append({
                'type': 'Performance',
                'severity': 'medium',
                'title': 'Synchronous XMLHttpRequest',
                'description': 'Page uses synchronous XMLHttpRequest. This blocks the main thread and prevents user interaction.',
                'fix': 'Use asynchronous XMLHttpRequest or fetch API. Consider using async/await pattern.'
            })
        
        total_requests = len(soup.find_all('script', src=True)) + len(soup.find_all('link', rel='stylesheet')) + len(images) + len(soup.find_all('iframe'))
        if total_requests > 50:
            issues.append({
                'type': 'Performance',
                'severity': 'medium',
                'title': 'Too Many HTTP Requests',
                'description': f'Page makes {total_requests} resource requests. Each request adds latency. Recommended under 50 for good performance.',
                'fix': 'Combine files, use CSS sprites, inline small resources, implement code splitting, remove unused resources.'
            })
        
        web_fonts = soup.find_all('link', rel='stylesheet', href=lambda x: x and 'font' in x.lower())
        if web_fonts:
            issues.append({
                'type': 'Performance',
                'severity': 'low',
                'title': 'Web Fonts Without Loading Strategy',
                'description': f'Found {len(web_fonts)} web font stylesheet(s) without font-display strategy. Causes invisible text during load.',
                'fix': 'Add font-display: swap to @font-face rules. Use font loading API for better control. Consider system fonts.'
            })
        
        scripts = soup.find_all('script')
        unminified = sum(1 for s in scripts if s.get('src') and not s.get('src').endswith('.min.js'))
        if unminified > 3:
            issues.append({
                'type': 'Performance',
                'severity': 'low',
                'title': 'Unminified JavaScript',
                'description': f'Found {unminified} JavaScript files that may not be minified. Minification reduces file size by 30-60%.',
                'fix': 'Minify all JavaScript files using terser or similar tools. Enable minification in build process.'
            })
        
        return issues
    
    def _ai_analysis(self, results, soup, html_content):
        try:
            security_summary = '\n'.join([f"- [{issue['severity'].upper()}] {issue['title']}: {issue['description']}" for issue in results['security_issues']])
            ui_summary = '\n'.join([f"- [{issue['severity'].upper()}] {issue['title']}: {issue['description']}" for issue in results['ui_issues']])
            perf_summary = '\n'.join([f"- [{issue['severity'].upper()}] {issue['title']}: {issue['description']}" for issue in results['performance_issues']])
            
            prompt = f"""You are a senior web security and performance engineer. Analyze this audit report for {self.url} and provide a structured, actionable report.

=== SECURITY ISSUES ({len(results['security_issues'])}) ===
{security_summary if security_summary else 'None'}

=== UI/UX ISSUES ({len(results['ui_issues'])}) ===
{ui_summary if ui_summary else 'None'}

=== PERFORMANCE ISSUES ({len(results['performance_issues'])}) ===
{perf_summary if perf_summary else 'None'}

Provide analysis in this EXACT format:

## Overall Health
[2-3 sentences assessing the website's overall security, usability, and performance posture]

## Critical Actions Required
1. [Most critical issue with specific remediation steps]
2. [Second most critical issue]
3. [Third most critical issue]

## Security Deep Dive
- [Explain the most significant security risk in plain language]
- [Explain potential impact and attack vectors]
- [Provide specific code/config examples for the fix]

## UI/UX Improvements
- [Prioritized list of UI/UX fixes with rationale]

## Performance Optimization
- [Prioritized list of performance improvements with expected impact]

## Implementation Roadmap
Week 1: [Critical fixes]
Week 2: [High priority fixes]
Week 3: [Medium/Low priority improvements]

Keep language technical but understandable. Focus on exploit scenarios and business impact."""

            response = self.client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a senior web security engineer and performance consultant. Provide structured, actionable analysis with specific technical details. Never say you are an AI."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.7
            )
            
            return response.choices[0].message.content
        except Exception as e:
            return f"AI analysis temporarily unavailable: {str(e)}"
    
    def _generate_recommendations(self, results):
        recommendations = []
        
        if results['security_issues']:
            recommendations.append({
                'category': 'Security',
                'priority': 'Critical',
                'actions': [
                    'Enable HTTPS with valid SSL certificate and HSTS',
                    'Implement Content-Security-Policy header',
                    'Add all security headers (X-Frame-Options, X-Content-Type-Options, etc.)',
                    'Remove inline event handlers and dangerous JS patterns (eval, document.write)',
                    'Add CSRF protection to all state-changing forms',
                    'Configure secure cookie flags (Secure, HttpOnly, SameSite)',
                    'Restrict access to sensitive files (.git, .env, etc.)',
                    'Add Subresource Integrity to CDN resources'
                ]
            })
        
        if results['ui_issues']:
            recommendations.append({
                'category': 'UI/UX & Accessibility',
                'priority': 'High',
                'actions': [
                    'Add viewport meta tag for mobile responsiveness',
                    'Add descriptive alt text to all images',
                    'Fix heading hierarchy (one H1, sequential H2-H6)',
                    'Add lang attribute to HTML tag',
                    'Add charset meta tag (UTF-8)',
                    'Add favicon',
                    'Add explicit labels to all form inputs',
                    'Add table headers (th) for data tables',
                    'Remove empty links/buttons or add aria-label'
                ]
            })
        
        if results['performance_issues']:
            recommendations.append({
                'category': 'Performance',
                'priority': 'High',
                'actions': [
                    'Enable gzip or brotli compression (60-80% size reduction)',
                    'Add Cache-Control headers with max-age for static assets',
                    'Compress images and convert to WebP/AVIF formats',
                    'Add width/height to images to prevent layout shift',
                    'Inline critical CSS and defer non-critical CSS',
                    'Add async/defer to JavaScript in head',
                    'Lazy load below-fold images',
                    'Reduce DOM size and nesting depth',
                    'Add resource hints (preconnect) for third-party origins'
                ]
            })
        
        return recommendations
    
    def _calculate_severity(self, results):
        total = len(results['security_issues']) + len(results['ui_issues']) + len(results['performance_issues'])
        
        high_count = sum(1 for issue in results['security_issues'] + results['ui_issues'] + results['performance_issues'] 
                        if issue.get('severity') == 'high')
        medium_count = sum(1 for issue in results['security_issues'] + results['ui_issues'] + results['performance_issues'] 
                          if issue.get('severity') == 'medium')
        critical_count = sum(1 for issue in results['security_issues'] + results['ui_issues'] + results['performance_issues'] 
                            if issue.get('severity') == 'critical')
        
        if critical_count > 0 or high_count > 3:
            return 'Critical'
        elif high_count > 0 or medium_count > 5:
            return 'High'
        elif total > 5:
            return 'Medium'
        elif total > 0:
            return 'Low'
        else:
            return 'Good'
