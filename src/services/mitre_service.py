import requests
import json
from datetime import datetime
from config import Config

class MitreService:
    """Service for fetching MITRE ATT&CK framework data"""
    
    def __init__(self):
        self.base_url = Config.MITRE_ATTACK_URL
        
    def fetch_attack_data(self):
        """Fetch MITRE ATT&CK framework data"""
        try:
            print("Fetching MITRE ATT&CK data...")
            response = requests.get(self.base_url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract techniques and tactics
            techniques = []
            tactics = []
            
            for obj in data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    # This is a technique
                    technique = {
                        'id': obj.get('external_references', [{}])[0].get('external_id', ''),
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'tactics': [phase.get('phase_name', '') for phase in obj.get('kill_chain_phases', [])],
                        'platforms': obj.get('x_mitre_platforms', []),
                        'data_sources': obj.get('x_mitre_data_sources', []),
                        'detection': obj.get('x_mitre_detection', ''),
                        'date': datetime.now().isoformat(),
                        'source': 'MITRE ATT&CK'
                    }
                    techniques.append(technique)
                
                elif obj.get('type') == 'x-mitre-tactic':
                    # This is a tactic
                    tactic = {
                        'id': obj.get('external_references', [{}])[0].get('external_id', ''),
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'short_name': obj.get('x_mitre_shortname', ''),
                        'date': datetime.now().isoformat()
                    }
                    tactics.append(tactic)
            
            print(f"Fetched {len(techniques)} techniques and {len(tactics)} tactics from MITRE")
            return {
                'techniques': techniques,
                'tactics': tactics,
                'last_updated': datetime.now().isoformat()
            }
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching MITRE data: {e}")
            return None
        except Exception as e:
            print(f"Error processing MITRE data: {e}")
            return None
    
    def get_technique_by_id(self, technique_id):
        """Get a specific technique by ID"""
        # This would typically query a database or cache
        # For now, we'll implement a basic version
        pass
    
    def search_techniques(self, query):
        """Search techniques by name or description"""
        # This would implement search functionality
        pass