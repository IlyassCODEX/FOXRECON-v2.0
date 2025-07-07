import re
import requests
from urllib.parse import urlparse
import json
from bs4 import BeautifulSoup
import os
import warnings
from typing import List, Dict, Tuple, Optional
import dns.resolver

warnings.filterwarnings('ignore', category=UserWarning, module='bs4')

class TechnologyDetector:
    def __init__(self):
        # Load fingerprint databases
        self.tech_db = self._load_tech_db()
        self.cloud_db = self._load_cloud_db()
        self.cdn_db = self._load_cdn_db()
        self.secret_patterns = self._load_secret_patterns()
        
    def _load_tech_db(self) -> Dict:
        """Load technology fingerprint database"""
        # This would normally be loaded from a file or external source
        return {
            'web_servers': {
                'nginx': {'headers': ['server'], 'pattern': r'nginx/?(\d+\.\d+\.\d+)?'},
                'apache': {'headers': ['server'], 'pattern': r'Apache/?(\d+\.\d+\.\d+)?'},
            },
            'programming': {
                'php': {'headers': ['x-powered-by'], 'pattern': r'PHP/?(\d+\.\d+\.\d+)?'},
                'node.js': {'headers': ['x-powered-by'], 'pattern': r'Express'},
            },
            'frameworks': {
                'wordpress': {'pattern': r'wp-content|wp-includes'},
                'django': {'headers': ['x-frame-options'], 'pattern': r'csrftoken'},
            },
            # More technologies would be added here
        }
    
    def _load_cloud_db(self) -> Dict:
        """Load cloud hosting fingerprint database"""
        return {
            'aws': {
                's3': {'dns': r's3\.amazonaws\.com', 'pattern': r'<Error><Code>AccessDenied</Code>'},
                'ec2': {'headers': ['x-amz-id-2', 'x-amz-request-id']},
                'cloudfront': {'headers': ['x-amz-cf-id']},
            },
            'azure': {
                'blob': {'dns': r'blob\.core\.windows\.net'},
                'websites': {'dns': r'azurewebsites\.net'},
            },
            'gcp': {
                'storage': {'dns': r'storage\.googleapis\.com'},
                'appengine': {'dns': r'appspot\.com'},
            }
        }
    
    def _load_cdn_db(self) -> Dict:
        """Load CDN fingerprint database"""
        return {
            'cloudflare': {
                'headers': ['server', 'cf-ray'],
                'dns': ['cloudflare'],
                'ips': self._get_cloudflare_ips()
            },
            'akamai': {
                'headers': ['server', 'x-akamai'],
                'dns': ['akamai'],
            },
            'fastly': {
                'headers': ['x-fastly'],
            }
        }
    
    def _get_cloudflare_ips(self) -> List[str]:
        """Get Cloudflare IP ranges"""
        try:
            response = requests.get('https://www.cloudflare.com/ips-v4')
            return response.text.split('\n')[:-1]
        except:
            return [
                '103.21.244.0/22',
                '103.22.200.0/22',
                '103.31.4.0/22',
                # More Cloudflare IPs
            ]
    
    def _load_secret_patterns(self) -> List[Dict]:
        """Load patterns for detecting secrets in JS files"""
        return [
            {'name': 'AWS API Key', 'pattern': r'AKIA[0-9A-Z]{16}'},
            {'name': 'AWS Secret Key', 'pattern': r'[0-9a-zA-Z/+]{40}'},
            {'name': 'Google API Key', 'pattern': r'AIza[0-9A-Za-z\-_]{35}'},
            {'name': 'Database URL', 'pattern': r'(postgres|mysql|mongodb)://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9\-\.]+:[0-9]+/[a-zA-Z0-9_]+'},
            {'name': 'API Key', 'pattern': r'api[_-]?key[=:][a-zA-Z0-9_\-]+'},
            {'name': 'Access Token', 'pattern': r'access[_-]?token[=:][a-zA-Z0-9_\-]+'},
        ]
    
    def detect_technologies(self, url: str, html: str = None, headers: Dict = None) -> Dict:
        """Detect technologies used by a website with improved error handling"""
        results = {
        'technologies': [],
        'cloud': None,
        'cdn': None,
        'exposed_files': [],
        'secrets': [],
        'endpoints': []
        }
    
        try:
            if not headers:
                try:
                    response = requests.get(url, timeout=10, verify=False)
                    headers = dict(response.headers)
                    html = response.text
                except Exception as e:
                    print(f"Could not fetch {url} for tech detection: {str(e)}")
                    return results
        
            # Safe header access
            headers = headers or {}
            html = html or ""
        
            # Detect web technologies with safe dictionary access
            try:
                results['technologies'] = self._detect_tech_from_headers(headers, html)
            except Exception as e:
                print(f"Tech detection from headers failed for {url}: {str(e)}")
        
            # Detect cloud hosting
            try:
                results['cloud'] = self._detect_cloud(url, headers, html)
            except Exception as e:
                print(f"Cloud detection failed for {url}: {str(e)}")
        
            # Detect CDN
            try:
                results['cdn'] = self._detect_cdn(url, headers)
            except Exception as e:
                print(f"CDN detection failed for {url}: {str(e)}")
        
            # Check for exposed files
            try:
                results['exposed_files'] = self._check_exposed_files(url)
            except Exception as e:
                print(f"Exposed files check failed for {url}: {str(e)}")
        
            # Analyze JavaScript files for secrets and endpoints
            if html:
                try:
                    js_urls = self._extract_js_urls(url, html)
                    for js_url in js_urls[:3]:  # Reduced from 5 to 3 to limit requests
                        try:
                            secrets, endpoints = self._analyze_js_file(js_url)
                            results['secrets'].extend(secrets)
                            results['endpoints'].extend(endpoints)
                        except Exception as e:
                            print(f"JS analysis failed for {js_url}: {str(e)}")
                except Exception as e:
                    print(f"JS URL extraction failed for {url}: {str(e)}")
    
        except Exception as e:
            print(f"Technology detection completely failed for {url}: {str(e)}")
    
        return results
    
    def _detect_tech_from_headers(self, headers: Dict, html: str) -> List[Dict]:
        """Detect technologies from HTTP headers and HTML"""
        detected = []
        
        for category, technologies in self.tech_db.items():
            for tech, patterns in technologies.items():
                # Check headers
                if 'headers' in patterns:
                    for header in patterns['headers']:
                        if header.lower() in (h.lower() for h in headers):
                            version = None
                            if 'pattern' in patterns:
                                match = re.search(patterns['pattern'], headers[header], re.I)
                                if match and len(match.groups()) > 0:
                                    version = match.group(1)
                            detected.append({
                                'name': tech,
                                'version': version,
                                'category': category,
                                'confidence': 100,
                                'source': f'header: {header}'
                            })
                            break
                
                # Check HTML patterns
                if html and 'pattern' in patterns:
                    if re.search(patterns['pattern'], html, re.I):
                        version = None
                        if 'version' in patterns:
                            match = re.search(patterns['version'], html, re.I)
                            if match:
                                version = match.group(1)
                        detected.append({
                            'name': tech,
                            'version': version,
                            'category': category,
                            'confidence': 90,
                            'source': 'html pattern'
                        })
        
        return detected
    
    def _detect_cloud(self, url: str, headers: Dict, html: str) -> Optional[Dict]:
        """Detect cloud hosting provider"""
        domain = urlparse(url).netloc
        
        for provider, services in self.cloud_db.items():
            for service, patterns in services.items():
                # Check DNS
                if 'dns' in patterns:
                    if re.search(patterns['dns'], domain, re.I):
                        return {
                            'provider': provider,
                            'service': service,
                            'confidence': 100
                        }
                
                # Check headers
                if headers and 'headers' in patterns:
                    for header in patterns['headers']:
                        if header.lower() in (h.lower() for h in headers):
                            return {
                                'provider': provider,
                                'service': service,
                                'confidence': 90
                            }
                
                # Check HTML patterns
                if html and 'pattern' in patterns:
                    if re.search(patterns['pattern'], html, re.I):
                        return {
                            'provider': provider,
                            'service': service,
                            'confidence': 80
                        }
        
        return None
    
    def _detect_cdn(self, url: str, headers: Dict) -> Optional[Dict]:
        """Detect CDN usage"""
        domain = urlparse(url).netloc
        
        for cdn, patterns in self.cdn_db.items():
            # Check headers
            if headers and 'headers' in patterns:
                for header in patterns['headers']:
                    if header.lower() in (h.lower() for h in headers):
                        return {
                            'provider': cdn,
                            'confidence': 100
                        }
            
            # Check DNS
            if 'dns' in patterns:
                for dns_pattern in patterns['dns']:
                    if dns_pattern in domain.lower():
                        return {
                            'provider': cdn,
                            'confidence': 90
                        }
            
            # Check IP ranges (for Cloudflare)
            if 'ips' in patterns:
                try:
                    ip = socket.gethostbyname(domain)
                    for ip_range in patterns['ips']:
                        if self._ip_in_range(ip, ip_range):
                            return {
                                'provider': cdn,
                                'confidence': 95
                            }
                except:
                    pass
        
        return None
    
    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in a CIDR range"""
        # Implementation omitted for brevity
        return False
    
    def _check_exposed_files(self, url: str) -> List[Dict]:
        """Check for common exposed files (.git, .env, etc.)"""
        exposed = []
        paths = [
        '/.git/HEAD',
        '/.env',
        '/.htaccess',
        '/robots.txt',
        '/sitemap.xml',
        '/phpinfo.php',
        '/admin/config.php',
        '/.git/config',
        '/.gitignore',
        '/.DS_Store',
        '/.svn/entries',
        '/.hg/hgrc',
        '/.bzr/branch/branch.conf',
        '/composer.lock',
        '/composer.json',
        '/package.json',
        '/yarn.lock',
        '/docker-compose.yml',
        '/docker-compose.yaml',
        '/Dockerfile',
        '/config.php',
        '/wp-config.php',
        '/config.yaml',
        '/config.yml',
        '/config.json',
        '/database.sql',
        '/db.sql',
        '/backup.sql',
        '/dump.sql',
        '/backup.zip',
        '/backup.tar.gz',
        '/admin/.env',
        '/admin/.git/HEAD',
        '/admin/.htpasswd',
        '/admin/.git/config',
        '/admin/config.yaml',
        '/admin/config.yml',
        '/admin/config.json',
        '/storage/.env',
        '/storage/.git/HEAD',
        '/storage/.htaccess',
        '/storage/config.php',
        '/api/.env',
        '/api/.git/HEAD',
        '/api/.htaccess',
        '/api/config.php',
        '/logs/error.log',
        '/logs/access.log',
        '/error.log',
        '/access.log',
        '/server-status',
        '/server-info'
        ]

        base_url = url.rstrip('/')
        for path in paths:
            try:
                full_url = f"{base_url}{path}"
                response = requests.get(full_url, timeout=5, verify=False)
                if response.status_code == 200:
                    exposed.append({
                    'url': full_url,
                    'path': path,
                    'status': response.status_code,
                    'content_type': response.headers.get('content-type', '')
                    })
            except:
                continue

        return exposed
    
    def _extract_js_urls(self, url: str, html: str) -> List[str]:
        """Extract JavaScript file URLs from HTML"""
        js_urls = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for script in soup.find_all('script'):
            if script.get('src'):
                src = script.get('src')
                if not src.startswith(('http://', 'https://')):
                    src = self._make_absolute(url, src)
                js_urls.append(src)
        
        return js_urls
    
    def _make_absolute(self, base_url: str, relative_url: str) -> str:
        """Convert relative URL to absolute"""
        base = urlparse(base_url)
        if relative_url.startswith('//'):
            return f"{base.scheme}:{relative_url}"
        elif relative_url.startswith('/'):
            return f"{base.scheme}://{base.netloc}{relative_url}"
        else:
            return f"{base.scheme}://{base.netloc}/{relative_url}"
    
    def _analyze_js_file(self, url: str) -> Tuple[List[Dict], List[Dict]]:
        """Analyze JavaScript file for secrets and API endpoints"""
        secrets = []
        endpoints = []
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                content = response.text
                
                # Detect secrets
                for pattern in self.secret_patterns:
                    matches = re.finditer(pattern['pattern'], content)
                    for match in matches:
                        secrets.append({
                            'type': pattern['name'],
                            'match': match.group(0),
                            'context': self._get_context(content, match.start(), match.end()),
                            'file': url
                        })
                
                # Detect API endpoints
                endpoint_patterns = [
                    r'https?://[a-zA-Z0-9\-\.]+/api/v[0-9]/[a-zA-Z0-9\-_/]+',
                    r'fetch\(["\'](https?://[^"\']+)["\']\)',
                    r'axios\.(get|post|put|delete)\(["\'](https?://[^"\']+)["\']\)'
                ]
                
                for pattern in endpoint_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        endpoint = match.group(1) if 'axios' in pattern else match.group(0)
                        endpoints.append({
                            'url': endpoint,
                            'method': 'GET' if 'get' in pattern.lower() else 'POST',
                            'source': url
                        })
        
        except:
            pass
        
        return secrets, endpoints
    
    def _get_context(self, text: str, start: int, end: int, chars: int = 50) -> str:
        """Get surrounding context for a matched pattern"""
        context_start = max(0, start - chars)
        context_end = min(len(text), end + chars)
        return text[context_start:context_end]
