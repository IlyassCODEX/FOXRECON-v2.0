# port_scanner.py
import nmap
import time
from concurrent.futures import ThreadPoolExecutor
from utils.helpers import is_ip_address, is_public_ip

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.risky_ports = {
            # Format: port: (risk_level, service_name, common_vulns)
            22: ('high', 'SSH', 'Brute force, weak credentials'),
            21: ('high', 'FTP', 'Anonymous auth, data leaks'),
            3389: ('high', 'RDP', 'BlueKeep, brute force'),
            445: ('critical', 'SMB', 'EternalBlue, ransomware'),
            6379: ('high', 'Redis', 'Unauthenticated access'),
            27017: ('high', 'MongoDB', 'No auth by default'),
            9200: ('medium', 'Elasticsearch', 'Data exposure'),
            5984: ('medium', 'CouchDB', 'Misconfigurations'),
            1433: ('high', 'MSSQL', 'Brute force, injection'),
            3306: ('medium', 'MySQL', 'Weak credentials'),
            5432: ('medium', 'PostgreSQL', 'Injection attacks'),
            8080: ('medium', 'HTTP-Alt', 'Web app vulnerabilities')
        }
        self.common_web_ports = [80, 443, 8080, 8443, 8000, 8888]
        self.vuln_scripts = [
            'vulners', 
            'vuln',
            'http-vuln-*',
            'smb-vuln-*',
            'ssl-*',
            'ftp-vuln*'
        ]

    def scan_target(self, target, ports='1-1000', vuln_scan=False):
        """Scan a single target with specified ports"""
        if not is_public_ip(target.split(':')[0]) and not target.startswith(('http://', 'https://')):
            return None

        try:
            print(f"Scanning {target} on ports {ports}...")
            
            # Basic scan first
            scan_args = '-sV --open'
            if vuln_scan:
                scan_args += ' --script=' + ','.join(self.vuln_scripts)
                
            self.nm.scan(hosts=target, ports=ports, arguments=scan_args)
            return self._parse_results(target, vuln_scan)
        except Exception as e:
            print(f"Scan failed for {target}: {str(e)}")
            return None

    def _parse_results(self, target, vuln_scan=False):
        """Parse nmap scan results into structured data"""
        if target not in self.nm.all_hosts():
            return None

        host_data = {
            'target': target,
            'ports': [],
            'services': [],
            'risky_ports': [],
            'vulnerabilities': [],
            'os_guess': self.nm[target].get('osmatch', [{}])[0].get('name', 'Unknown'),
            'scan_time': time.time()
        }

        for proto in self.nm[target].all_protocols():
            ports = self.nm[target][proto].keys()
            for port in ports:
                port_data = {
                    'port': port,
                    'protocol': proto,
                    'state': self.nm[target][proto][port]['state'],
                    'service': self.nm[target][proto][port]['name'],
                    'version': self.nm[target][proto][port].get('version', ''),
                    'risk': self._get_port_risk(port)
                }
                
                # Add vulnerability info if vuln scan was performed
                if vuln_scan:
                    port_data['vulnerabilities'] = self._get_vulnerabilities(target, proto, port)
                
                host_data['ports'].append(port_data)

                # Categorize services
                if port_data['service'] not in host_data['services']:
                    host_data['services'].append(port_data['service'])

                # Flag risky ports
                if port_data['risk']['level'] in ['high', 'critical']:
                    host_data['risky_ports'].append(port_data)
                    
                # Collect all vulnerabilities
                if vuln_scan and port_data.get('vulnerabilities'):
                    host_data['vulnerabilities'].extend(port_data['vulnerabilities'])

        return host_data

    def _get_vulnerabilities(self, target, protocol, port):
        """Extract vulnerability information from Nmap script results"""
        try:
            script_results = self.nm[target][protocol][port].get('script', {})
            vulns = []
            
            for script_name, output in script_results.items():
                if 'vuln' in script_name.lower() or 'vulners' in script_name.lower():
                    if isinstance(output, str):
                        # Simple string output
                        vulns.append({
                            'script': script_name,
                            'output': output
                        })
                    elif isinstance(output, list):
                        # Structured output
                        for item in output:
                            vulns.append({
                                'script': script_name,
                                'output': str(item)
                            })
                    elif isinstance(output, dict):
                        # Detailed vulnerability info
                        output['script'] = script_name
                        vulns.append(output)
            
            return vulns
        except Exception as e:
            print(f"Error parsing vulnerabilities: {e}")
            return []

    def _get_port_risk(self, port):
        """Determine risk level for a given port"""
        if port in self.risky_ports:
            level, service, vulns = self.risky_ports[port]
            return {
                'level': level,
                'service': service,
                'vulnerabilities': vulns
            }
        return {
            'level': 'low',
            'service': '',
            'vulnerabilities': ''
        }

    def batch_scan(self, targets, ports='80,443,22,3389,445', vuln_scan=False):
        """Scan multiple targets efficiently"""
        results = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:  # Reduced workers for resource-intensive scans
            futures = [executor.submit(self.scan_target, target, ports, vuln_scan) for target in targets]
            for future in futures:
                result = future.result()
                if result:
                    results.append(result)
        
        return results

    def quick_web_scan(self, target, vuln_scan=False):
        """Fast scan for common web ports"""
        return self.scan_target(target=target, ports=','.join(map(str, self.common_web_ports)), vuln_scan=vuln_scan)

    def full_vulnerability_scan(self, target):
        """Comprehensive vulnerability scan with all scripts"""
        return self.scan_target(target, ports='1-1000', vuln_scan=True)
