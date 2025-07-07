# modules/enumeration.py
import requests
import re
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple
from bs4 import BeautifulSoup

class EmailUserEnumerator:
    def __init__(self, hunterio_api_key: str = None):
        self.hunterio_api_key = "" # here u can make ur hunterio_api_key
        self.common_login_paths = [
            '/login', '/signin', '/auth', '/oauth', 
            '/admin', '/wp-login.php', '/log-in',
            '/sign-in', '/account/login', '/user/login'
        ]
        self.password_reset_paths = [
            '/password-reset', '/reset-password', '/forgot-password',
            '/account/recovery', '/user/password', '/wp-login.php?action=lostpassword'
        ]

    def find_email_patterns(self, domain: str) -> Dict:
        """Find email patterns using Hunter.io API and web scraping"""
        results = {
            'email_formats': [],
            'found_emails': [],
            'login_pages': [],
            'password_reset_pages': []
        }

        # Hunter.io API integration
        if self.hunterio_api_key:
            try:
                hunter_url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={self.hunterio_api_key}"
                response = requests.get(hunter_url)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('data', {}).get('pattern'):
                        results['email_formats'].append({
                            'pattern': data['data']['pattern'],
                            'confidence': data['data']['pattern_score'],
                            'source': 'hunter.io'
                        })
                    if data.get('data', {}).get('emails'):
                        results['found_emails'].extend([
                            {'email': e['value'], 'type': e['type'], 'confidence': e['confidence']}
                            for e in data['data']['emails']
                        ])
            except Exception as e:
                print(f"Hunter.io API error: {e}")

        # Web scraping for email patterns
        try:
            response = requests.get(f"https://{domain}", timeout=10)
            if response.status_code == 200:
                # Look for email addresses in the page
                found_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', response.text)
                results['found_emails'].extend([
                    {'email': email, 'type': 'scraped', 'confidence': 70}
                    for email in set(found_emails) if email.endswith(domain)
                ])
                
                # Look for common login pages
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href'].lower()
                    if any(path in href for path in self.common_login_paths):
                        login_url = href if href.startswith('http') else f"https://{domain}{href}"
                        results['login_pages'].append({
                            'url': login_url,
                            'type': 'potential_login',
                            'source': 'web_scraping'
                        })
                    
                    if any(path in href for path in self.password_reset_paths):
                        reset_url = href if href.startswith('http') else f"https://{domain}{href}"
                        results['password_reset_pages'].append({
                            'url': reset_url,
                            'type': 'password_reset',
                            'source': 'web_scraping'
                        })
        except Exception as e:
            print(f"Web scraping error for {domain}: {e}")

        return results

    def enumerate_from_subdomains(self, subdomains: List[Dict]) -> Dict:
        """Enumerate email and user info from subdomains"""
        results = {
            'email_analysis': {},
            'login_pages': [],
            'password_reset_pages': []
        }

        for subdomain in subdomains:
            if not subdomain.get('http_status') and not subdomain.get('https_status'):
                continue
                
            url = f"https://{subdomain['subdomain']}" if subdomain.get('https_status') else f"http://{subdomain['subdomain']}"
            
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    # Check for common login pages
                    parsed_url = urlparse(response.url)
                    path = parsed_url.path.lower()
                    
                    if any(login_path in path for login_path in self.common_login_paths):
                        results['login_pages'].append({
                            'url': response.url,
                            'subdomain': subdomain['subdomain'],
                            'status': response.status_code,
                            'type': 'login_page'
                        })
                    
                    if any(reset_path in path for reset_path in self.password_reset_paths):
                        results['password_reset_pages'].append({
                            'url': response.url,
                            'subdomain': subdomain['subdomain'],
                            'status': response.status_code,
                            'type': 'password_reset'
                        })
                    
                    # Check for Office 365 or GSuite login
                    if 'login.microsoftonline.com' in response.text:
                        results['login_pages'].append({
                            'url': response.url,
                            'subdomain': subdomain['subdomain'],
                            'status': response.status_code,
                            'type': 'office365_login'
                        })
                    
                    if 'accounts.google.com' in response.text:
                        results['login_pages'].append({
                            'url': response.url,
                            'subdomain': subdomain['subdomain'],
                            'status': response.status_code,
                            'type': 'gsuite_login'
                        })
            except Exception as e:
                continue

        return results
