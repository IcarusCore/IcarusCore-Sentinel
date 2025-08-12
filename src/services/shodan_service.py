import requests
import json
from datetime import datetime
from config import Config

class ShodanService:
    """Service for fetching threat intelligence from Shodan"""
    
    def __init__(self):
        self.api_key = Config.SHODAN_API_KEY
        self.base_url = 'https://api.shodan.io'
        
    def fetch_vulnerabilities(self, limit=50):
        """Fetch recent vulnerability data from Shodan"""
        if not self.api_key:
            print("Shodan API key not configured, skipping Shodan data fetch")
            return None
            
        try:
            print("Fetching Shodan vulnerability data...")
            
            # Search for recent vulnerabilities
            url = f"{self.base_url}/shodan/host/search"
            params = {
                'key': self.api_key,
                'query': 'vuln:CVE-2023 country:US',  # Recent CVEs in US
                'limit': limit
            }
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = []
            
            for result in data.get('matches', []):
                vuln_data = {
                    'id': f"shodan-{result.get('ip_str', '')}-{datetime.now().strftime('%Y%m%d')}",
                    'name': f"Vulnerable Service on {result.get('ip_str', 'Unknown IP')}",
                    'description': self._build_description(result),
                    'ip_address': result.get('ip_str', ''),
                    'port': result.get('port', 0),
                    'service': result.get('product', 'Unknown Service'),
                    'version': result.get('version', ''),
                    'country': result.get('location', {}).get('country_name', ''),
                    'city': result.get('location', {}).get('city', ''),
                    'organization': result.get('org', ''),
                    'hostnames': result.get('hostnames', []),
                    'vulnerabilities': result.get('vulns', []),
                    'severity': self._assess_severity(result),
                    'source': 'Shodan',
                    'date': datetime.now().isoformat(),
                    'last_updated': result.get('timestamp', ''),
                    'tags': self._extract_tags(result)
                }
                vulnerabilities.append(vuln_data)
            
            print(f"Fetched {len(vulnerabilities)} vulnerabilities from Shodan")
            return vulnerabilities
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching Shodan data: {e}")
            return None
        except Exception as e:
            print(f"Error processing Shodan data: {e}")
            return None
    
    
    def fetch_host_info(self, ip_address):
        """Fetch detailed information about a specific host"""
        if not self.api_key:
            return None
            
        try:
            url = f"{self.base_url}/shodan/host/{ip_address}"
            params = {'key': self.api_key}
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            print(f"Error fetching host info for {ip_address}: {e}")
            return None
    
    def search_exploits(self, query, limit=20):
        """Search for exploits in Shodan's exploit database"""
        if not self.api_key:
            return None
            
        try:
            url = f"{self.base_url}/api/search"
            params = {
                'key': self.api_key,
                'query': query,
                'limit': limit
            }
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            exploits = []
            
            for exploit in data.get('matches', []):
                exploit_data = {
                    'id': exploit.get('_id', ''),
                    'title': exploit.get('_source', {}).get('title', ''),
                    'description': exploit.get('_source', {}).get('description', ''),
                    'type': exploit.get('_source', {}).get('type', ''),
                    'platform': exploit.get('_source', {}).get('platform', ''),
                    'date': exploit.get('_source', {}).get('date', ''),
                    'author': exploit.get('_source', {}).get('author', ''),
                    'cve': exploit.get('_source', {}).get('cve', []),
                    'source': 'Shodan Exploits'
                }
                exploits.append(exploit_data)
            
            return exploits
            
        except Exception as e:
            print(f"Error searching exploits: {e}")
            return None
    
    def get_api_info(self):
        """Get information about the API key"""
        if not self.api_key:
            return None
            
        try:
            url = f"{self.base_url}/api-info"
            params = {'key': self.api_key}
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            print(f"Error getting API info: {e}")
            return None
    
    def _build_description(self, result):
        """Build a descriptive text for the vulnerability"""
        ip = result.get('ip_str', 'Unknown IP')
        service = result.get('product', 'Unknown Service')
        version = result.get('version', '')
        port = result.get('port', '')
        vulns = result.get('vulns', [])
        
        description = f"Vulnerable {service}"
        if version:
            description += f" (version {version})"
        description += f" detected on {ip}"
        if port:
            description += f" port {port}"
        
        if vulns:
            description += f". Known vulnerabilities: {', '.join(vulns[:3])}"
            if len(vulns) > 3:
                description += f" and {len(vulns) - 3} more"
        
        return description
    
    def _assess_severity(self, result):
        """Assess severity based on vulnerability information"""
        vulns = result.get('vulns', [])
        
        if not vulns:
            return 'Low'
        
        # Check for critical CVEs (this is a simplified assessment)
        critical_keywords = ['remote code execution', 'rce', 'critical', '10.0']
        high_keywords = ['privilege escalation', 'authentication bypass', 'high']
        
        vuln_text = ' '.join(vulns).lower()
        
        if any(keyword in vuln_text for keyword in critical_keywords):
            return 'Critical'
        elif any(keyword in vuln_text for keyword in high_keywords):
            return 'High'
        elif len(vulns) >= 3:
            return 'Medium'
        else:
            return 'Low'
    
    def _extract_tags(self, result):
        """Extract relevant tags from Shodan result"""
        tags = ['shodan', 'vulnerability-scan']
        
        # Add service-based tags
        service = result.get('product', '').lower()
        if 'http' in service or 'web' in service:
            tags.append('web-service')
        if 'ssh' in service:
            tags.append('ssh')
        if 'ftp' in service:
            tags.append('ftp')
        if 'database' in service or 'mysql' in service or 'postgres' in service:
            tags.append('database')
        
        # Add vulnerability tags
        vulns = result.get('vulns', [])
        if vulns:
            tags.append('vulnerable')
            if any('2023' in vuln for vuln in vulns):
                tags.append('recent-cve')
        
        # Add location tags
        country = result.get('location', {}).get('country_code', '')
        if country:
            tags.append(f'country-{country.lower()}')
        
        return tags
    
    def fetch_internet_scan_data(self, query='port:22,80,443', limit=100):
        """Fetch general internet scan data for threat landscape analysis"""
        if not self.api_key:
            return None
            
        try:
            print(f"Fetching Shodan scan data for: {query}")
            
            url = f"{self.base_url}/shodan/host/search"
            params = {
                'key': self.api_key,
                'query': query,
                'limit': limit
            }
            
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            scan_results = []
            
            for result in data.get('matches', []):
                scan_data = {
                    'id': f"scan-{result.get('ip_str', '')}-{result.get('port', '')}",
                    'name': f"Exposed Service: {result.get('product', 'Unknown')}",
                    'description': f"Exposed {result.get('product', 'service')} on {result.get('ip_str', 'unknown')}:{result.get('port', '')}",
                    'ip_address': result.get('ip_str', ''),
                    'port': result.get('port', 0),
                    'service': result.get('product', 'Unknown'),
                    'banner': result.get('data', '')[:200],  # First 200 chars of banner
                    'country': result.get('location', {}).get('country_name', ''),
                    'organization': result.get('org', ''),
                    'severity': 'Low',  # Default for exposure
                    'source': 'Shodan Scan',
                    'date': datetime.now().isoformat(),
                    'tags': ['exposure', 'internet-facing', result.get('product', '').lower()]
                }
                scan_results.append(scan_data)
            
            print(f"Fetched {len(scan_results)} scan results from Shodan")
            return scan_results
            
        except Exception as e:
            print(f"Error fetching scan data: {e}")
            return None