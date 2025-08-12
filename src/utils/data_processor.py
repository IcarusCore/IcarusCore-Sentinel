import json
import os
from datetime import datetime
from config import Config

class DataProcessor:
    """Process and store threat intelligence data from various sources"""
    
    def __init__(self):
        self.config = Config()
        
    def process_mitre_data(self, mitre_data):
        """Process MITRE ATT&CK data and update threat files"""
        try:
            techniques = mitre_data.get('techniques', [])
            
            # Load existing threats
            existing_threats = self._load_json_file(Config.THREATS_FILE)
            
            # Convert MITRE techniques to threat format
            for technique in techniques:
                threat = {
                    'id': technique.get('id', ''),
                    'name': technique.get('name', ''),
                    'description': technique.get('description', ''),
                    'tactic': ', '.join(technique.get('tactics', [])),
                    'platforms': technique.get('platforms', []),
                    'data_sources': technique.get('data_sources', []),
                    'detection': technique.get('detection', ''),
                    'mitigation': self._generate_mitigation_advice(technique),
                    'severity': 'Medium',  # Default severity for MITRE techniques
                    'source': 'MITRE ATT&CK',
                    'date': technique.get('date', ''),
                    'tags': ['mitre', 'technique'] + technique.get('tactics', [])
                }
                
                # Check if already exists (avoid duplicates)
                if not any(t.get('id') == threat['id'] and t.get('source') == 'MITRE ATT&CK' 
                          for t in existing_threats):
                    existing_threats.append(threat)
            
            # Save updated data
            self._save_json_file(Config.THREATS_FILE, existing_threats)
            
            # Process threat actors from MITRE data
            self._process_mitre_actors(mitre_data)
            
            print(f"Processed {len(techniques)} MITRE techniques")
            
        except Exception as e:
            print(f"Error processing MITRE data: {e}")
    
    def process_cisa_data(self, cisa_data):
        """Process CISA alerts and update threat files"""
        try:
            # Load existing threats
            existing_threats = self._load_json_file(Config.THREATS_FILE)
            
            for alert in cisa_data:
                threat = {
                    'id': alert.get('id', ''),
                    'name': alert.get('title', ''),
                    'description': alert.get('description', ''),
                    'tactic': 'Alert',
                    'severity': alert.get('severity', 'Medium'),
                    'source': 'CISA',
                    'date': alert.get('date', ''),
                    'link': alert.get('link', ''),
                    'tags': alert.get('tags', []) + ['cisa', 'alert'],
                    'mitigation': 'Follow CISA recommendations in the full alert.',
                    'detection': 'Monitor for indicators mentioned in the alert.'
                }
                
                # Check if already exists
                if not any(t.get('id') == threat['id'] and t.get('source') == 'CISA' 
                          for t in existing_threats):
                    existing_threats.append(threat)
            
            # Save updated data
            self._save_json_file(Config.THREATS_FILE, existing_threats)
            print(f"Processed {len(cisa_data)} CISA alerts")
            
        except Exception as e:
            print(f"Error processing CISA data: {e}")
    
    def process_rss_data(self, rss_data):
        """Process RSS feed data and update threat files"""
        try:
            # Load existing threats  
            existing_threats = self._load_json_file(Config.THREATS_FILE)
            
            for article in rss_data:
                threat = {
                    'id': article.get('id', ''),
                    'name': article.get('title', ''),
                    'description': article.get('description', ''),
                    'tactic': 'News/Intel',
                    'severity': article.get('threat_level', 'Low'),
                    'source': article.get('source', ''),
                    'date': article.get('date', ''),
                    'link': article.get('link', ''),
                    'tags': article.get('tags', []) + ['news'],
                    'author': article.get('author', ''),
                    'mitigation': 'Stay informed and follow security best practices.',
                    'detection': 'Monitor for related indicators and patterns.'
                }
                
                # Only add if not already exists and has relevant security tags
                if (not any(t.get('id') == threat['id'] for t in existing_threats) and
                    any(tag in ['malware', 'ransomware', 'vulnerability', 'apt', 'phishing'] 
                        for tag in article.get('tags', []))):
                    existing_threats.append(threat)
            
            # Keep only recent threats (last 1000)
            existing_threats.sort(key=lambda x: x.get('date', ''), reverse=True)
            existing_threats = existing_threats[:1000]
            
            # Save updated data
            self._save_json_file(Config.THREATS_FILE, existing_threats)
            print(f"Processed RSS data, total threats: {len(existing_threats)}")
            
        except Exception as e:
            print(f"Error processing RSS data: {e}")
    
    def process_otx_data(self, otx_data):
        """Process OTX pulse data and update threat files"""
        try:
            # Load existing threats
            existing_threats = self._load_json_file(Config.THREATS_FILE)
            
            for pulse in otx_data:
                threat = {
                    'id': f"otx-{pulse.get('id', '')}",
                    'name': pulse.get('name', ''),
                    'description': pulse.get('description', ''),
                    'tactic': 'Intelligence',
                    'severity': pulse.get('threat_level', 'Medium'),
                    'source': 'AlienVault OTX',
                    'date': pulse.get('date', ''),
                    'author': pulse.get('author', ''),
                    'tags': pulse.get('tags', []) + ['otx', 'pulse'],
                    'malware_families': pulse.get('malware_families', []),
                    'attack_ids': pulse.get('attack_ids', []),
                    'indicators_count': pulse.get('indicators_count', 0),
                    'mitigation': 'Review indicators and implement appropriate controls.',
                    'detection': f'Monitor for {pulse.get("indicators_count", 0)} associated indicators.'
                }
                
                # Check if already exists
                if not any(t.get('id') == threat['id'] for t in existing_threats):
                    existing_threats.append(threat)
            
            # Save updated data
            self._save_json_file(Config.THREATS_FILE, existing_threats)
            print(f"Processed {len(otx_data)} OTX pulses")
            
        except Exception as e:
            print(f"Error processing OTX data: {e}")
    
    def _process_mitre_actors(self, mitre_data):
        """Extract and process threat actor information from MITRE data"""
        try:
            # Load existing actors
            existing_actors = self._load_json_file(Config.ACTORS_FILE)
            
            # Common APT groups and their descriptions
            known_actors = [
                {
                    'id': 'apt1',
                    'name': 'APT1',
                    'description': 'Chinese cyber espionage group, also known as Comment Crew',
                    'country': 'China',
                    'targets': ['Government', 'Military', 'Private Companies'],
                    'techniques': ['Spear Phishing', 'Remote Access Tools', 'Data Exfiltration'],
                    'active_since': '2006',
                    'source': 'MITRE ATT&CK'
                },
                {
                    'id': 'apt28',
                    'name': 'APT28',
                    'description': 'Russian military intelligence cyber unit, also known as Fancy Bear',
                    'country': 'Russia',
                    'targets': ['Government', 'Military', 'Media'],
                    'techniques': ['Zero-day Exploits', 'Spear Phishing', 'Credential Harvesting'],
                    'active_since': '2007',
                    'source': 'MITRE ATT&CK'
                },
                {
                    'id': 'apt29',
                    'name': 'APT29',
                    'description': 'Russian intelligence service, also known as Cozy Bear',
                    'country': 'Russia',
                    'targets': ['Government', 'Healthcare', 'Technology'],
                    'techniques': ['Supply Chain Attacks', 'Living off the Land', 'Steganography'],
                    'active_since': '2008',
                    'source': 'MITRE ATT&CK'
                },
                {
                    'id': 'lazarus',
                    'name': 'Lazarus Group',
                    'description': 'North Korean state-sponsored group behind major cyber attacks',
                    'country': 'North Korea',
                    'targets': ['Financial', 'Cryptocurrency', 'Entertainment'],
                    'techniques': ['Destructive Malware', 'Financial Theft', 'Ransomware'],
                    'active_since': '2009',
                    'source': 'MITRE ATT&CK'
                }
            ]
            
            # Add known actors if not already present
            for actor in known_actors:
                if not any(a.get('id') == actor['id'] for a in existing_actors):
                    existing_actors.append(actor)
            
            # Save updated actors
            self._save_json_file(Config.ACTORS_FILE, existing_actors)
            
        except Exception as e:
            print(f"Error processing MITRE actors: {e}")
    
    def _generate_mitigation_advice(self, technique):
        """Generate basic mitigation advice for a technique"""
        tactics = technique.get('tactics', [])
        advice = []
        
        if 'initial-access' in tactics:
            advice.append('Implement email security and user training.')
        if 'execution' in tactics:
            advice.append('Use application control and endpoint protection.')
        if 'persistence' in tactics:
            advice.append('Monitor system changes and user accounts.')
        if 'credential-access' in tactics:
            advice.append('Implement multi-factor authentication.')
        if 'lateral-movement' in tactics:
            advice.append('Segment networks and monitor lateral traffic.')
        if 'exfiltration' in tactics:
            advice.append('Monitor data flows and implement DLP.')
        
        return ' '.join(advice) if advice else 'Follow security best practices and monitor for suspicious activity.'
    
    def _load_json_file(self, filepath):
        """Load JSON data from file"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"Error loading {filepath}: {e}")
            return []
    
    def _save_json_file(self, filepath, data):
        """Save JSON data to file"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving {filepath}: {e}")
    
    def update_tools_data(self):
        """Update tools and techniques data with common security tools"""
        try:
            tools = [
                {
                    'id': 'powershell',
                    'name': 'PowerShell',
                    'description': 'Command-line shell and scripting language often abused by attackers',
                    'category': 'Dual-use Tool',
                    'platforms': ['Windows'],
                    'used_by': ['APT28', 'APT29', 'FIN7'],
                    'techniques': ['T1059.001'],
                    'detection': 'Monitor PowerShell execution and command-line arguments',
                    'mitigation': 'Enable PowerShell logging and restrict execution policies',
                    'is_legitimate': True,
                    'availability': 'Built-in'
                },
                {
                    'id': 'mimikatz',
                    'name': 'Mimikatz',
                    'description': 'Tool for extracting passwords and authentication tokens from Windows',
                    'category': 'Credential Access',
                    'platforms': ['Windows'],
                    'used_by': ['Multiple APT groups'],
                    'techniques': ['T1003.001', 'T1558'],
                    'detection': 'Monitor for LSASS access and credential dumping activities',
                    'mitigation': 'Implement credential guard and limit admin privileges',
                    'is_legitimate': True,
                    'availability': 'Free'
                },
                {
                    'id': 'cobalt-strike',
                    'name': 'Cobalt Strike',
                    'description': 'Commercial penetration testing tool frequently used in attacks',
                    'category': 'Command and Control',
                    'platforms': ['Windows', 'Linux', 'macOS'],
                    'used_by': ['Ransomware groups', 'APT groups'],
                    'techniques': ['T1071', 'T1055'],
                    'detection': 'Monitor for beacon communications and process injection',
                    'mitigation': 'Block known C2 domains and monitor network traffic',
                    'is_legitimate': True,
                    'availability': 'Commercial'
                }
            ]
            
            self._save_json_file(Config.TOOLS_FILE, tools)
            print(f"Updated tools database with {len(tools)} entries")
            
        except Exception as e:
            print(f"Error updating tools data: {e}")