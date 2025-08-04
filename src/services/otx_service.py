import requests
from datetime import datetime
from config import Config

class OTXService:
    """Service for fetching threat intelligence from AlienVault OTX"""
    
    def __init__(self):
        self.api_key = Config.OTX_API_KEY
        self.base_url = 'https://otx.alienvault.com/api/v1'
        self.headers = {
            'X-OTX-API-KEY': self.api_key,
            'Content-Type': 'application/json'
        }
    
    def fetch_pulses(self, limit=50):
        """Fetch recent threat intelligence pulses"""
        if not self.api_key:
            print("OTX API key not configured, skipping OTX data fetch")
            return None
            
        try:
            print("Fetching OTX pulses...")
            
            # Fetch subscribed pulses (requires API key)
            url = f"{self.base_url}/pulses/subscribed"
            params = {'limit': limit, 'page': 1}
            
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            pulses = []
            
            for pulse in data.get('results', []):
                pulse_data = {
                    'id': pulse.get('id', ''),
                    'name': pulse.get('name', ''),
                    'description': pulse.get('description', ''),
                    'author': pulse.get('author_name', ''),
                    'created': pulse.get('created', ''),
                    'modified': pulse.get('modified', ''),
                    'tags': pulse.get('tags', []),
                    'references': pulse.get('references', []),
                    'malware_families': pulse.get('malware_families', []),
                    'attack_ids': pulse.get('attack_ids', []),
                    'industries': pulse.get('industries', []),
                    'targeted_countries': pulse.get('targeted_countries', []),
                    'indicators_count': len(pulse.get('indicators', [])),
                    'source': 'AlienVault OTX',
                    'date': datetime.now().isoformat(),
                    'threat_level': self._assess_pulse_threat_level(pulse)
                }
                pulses.append(pulse_data)
            
            print(f"Fetched {len(pulses)} OTX pulses")
            return pulses
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching OTX pulses: {e}")
            return None
        except Exception as e:
            print(f"Error processing OTX data: {e}")
            return None
    
    def fetch_indicators(self, pulse_id):
        """Fetch indicators for a specific pulse"""
        if not self.api_key:
            return None
            
        try:
            url = f"{self.base_url}/pulses/{pulse_id}/indicators"
            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            print(f"Error fetching indicators for pulse {pulse_id}: {e}")
            return None
    
    def _assess_pulse_threat_level(self, pulse):
        """Assess threat level based on pulse characteristics"""
        # Factors that increase threat level
        score = 0
        
        # Check tags for high-risk indicators
        tags = [tag.lower() for tag in pulse.get('tags', [])]
        high_risk_tags = ['apt', 'ransomware', 'zero-day', 'critical', 'active', 'campaign']
        medium_risk_tags = ['malware', 'phishing', 'trojan', 'backdoor']
        
        for tag in tags:
            if any(risk_tag in tag for risk_tag in high_risk_tags):
                score += 3
            elif any(risk_tag in tag for risk_tag in medium_risk_tags):
                score += 2
        
        # Check for malware families
        if pulse.get('malware_families'):
            score += 2
        
        # Check for MITRE ATT&CK references
        if pulse.get('attack_ids'):
            score += 2
        
        # Check for targeted countries/industries
        if pulse.get('targeted_countries') or pulse.get('industries'):
            score += 1
        
        # Determine threat level
        if score >= 6:
            return 'Critical'
        elif score >= 4:
            return 'High'
        elif score >= 2:
            return 'Medium'
        else:
            return 'Low'