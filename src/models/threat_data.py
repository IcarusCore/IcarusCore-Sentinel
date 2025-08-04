"""
Data models for threat intelligence information

This module defines the core data structures used throughout the application
for representing threat intelligence data.
"""

from datetime import datetime
from typing import List, Dict, Optional
import json

class ThreatData:
    """
    Represents a single threat intelligence item (TTP, vulnerability, etc.)
    """
    
    def __init__(self, 
                 id: str,
                 name: str,
                 description: str,
                 source: str,
                 severity: str = 'Medium',
                 tactic: str = '',
                 techniques: List[str] = None,
                 platforms: List[str] = None,
                 tags: List[str] = None,
                 date: str = None,
                 **kwargs):
        
        self.id = id
        self.name = name
        self.description = description
        self.source = source
        self.severity = severity
        self.tactic = tactic
        self.techniques = techniques or []
        self.platforms = platforms or []
        self.tags = tags or []
        self.date = date or datetime.now().isoformat()
        
        # Additional fields
        self.link = kwargs.get('link', '')
        self.author = kwargs.get('author', '')
        self.detection = kwargs.get('detection', '')
        self.mitigation = kwargs.get('mitigation', '')
        self.references = kwargs.get('references', [])
        self.cve_ids = kwargs.get('cve_ids', [])
        self.malware_families = kwargs.get('malware_families', [])
        self.attack_ids = kwargs.get('attack_ids', [])
        
        # Calculated fields
        self.threat_score = kwargs.get('threat_score', 0)
        self.is_recent = self._calculate_is_recent()
    
    def _calculate_is_recent(self) -> bool:
        """Determine if this threat is from the last 7 days"""
        try:
            threat_date = datetime.fromisoformat(self.date.replace('Z', '+00:00'))
            days_old = (datetime.now() - threat_date).days
            return days_old <= 7
        except:
            return False
    
    def to_dict(self) -> Dict:
        """Convert threat data to dictionary format"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'source': self.source,
            'severity': self.severity,
            'tactic': self.tactic,
            'techniques': self.techniques,
            'platforms': self.platforms,
            'tags': self.tags,
            'date': self.date,
            'link': self.link,
            'author': self.author,
            'detection': self.detection,
            'mitigation': self.mitigation,
            'references': self.references,
            'cve_ids': self.cve_ids,
            'malware_families': self.malware_families,
            'attack_ids': self.attack_ids,
            'threat_score': self.threat_score,
            'is_recent': self.is_recent
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ThreatData':
        """Create ThreatData instance from dictionary"""
        return cls(**data)
    
    def get_severity_level(self) -> int:
        """Get numeric severity level for sorting"""
        severity_levels = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1,
            'Unknown': 0
        }
        return severity_levels.get(self.severity, 0)
    
    def has_mitre_technique(self) -> bool:
        """Check if this threat has MITRE ATT&CK techniques"""
        return bool(self.attack_ids or any(t.startswith('T') for t in self.techniques))
    
    def get_primary_tactic(self) -> str:
        """Get the primary MITRE ATT&CK tactic"""
        if self.tactic and ',' in self.tactic:
            return self.tactic.split(',')[0].strip()
        return self.tactic or 'Unknown'


class ThreatActor:
    """
    Represents a threat actor or adversary group
    """
    
    def __init__(self,
                 id: str,
                 name: str,
                 description: str,
                 country: str = '',
                 aliases: List[str] = None,
                 targets: List[str] = None,
                 techniques: List[str] = None,
                 tools: List[str] = None,
                 active_since: str = '',
                 source: str = '',
                 **kwargs):
        
        self.id = id
        self.name = name
        self.description = description
        self.country = country
        self.aliases = aliases or []
        self.targets = targets or []
        self.techniques = techniques or []
        self.tools = tools or []
        self.active_since = active_since
        self.source = source
        
        # Additional fields
        self.motivation = kwargs.get('motivation', '')
        self.sophistication = kwargs.get('sophistication', 'Unknown')
        self.attribution_confidence = kwargs.get('attribution_confidence', 'Medium')
        self.last_activity = kwargs.get('last_activity', '')
        self.campaigns = kwargs.get('campaigns', [])
        self.malware_families = kwargs.get('malware_families', [])
        self.references = kwargs.get('references', [])
    
    def to_dict(self) -> Dict:
        """Convert threat actor to dictionary format"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'country': self.country,
            'aliases': self.aliases,
            'targets': self.targets,
            'techniques': self.techniques,
            'tools': self.tools,
            'active_since': self.active_since,
            'source': self.source,
            'motivation': self.motivation,
            'sophistication': self.sophistication,
            'attribution_confidence': self.attribution_confidence,
            'last_activity': self.last_activity,
            'campaigns': self.campaigns,
            'malware_families': self.malware_families,
            'references': self.references
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ThreatActor':
        """Create ThreatActor instance from dictionary"""
        return cls(**data)
    
    def is_apt_group(self) -> bool:
        """Check if this is an APT (Advanced Persistent Threat) group"""
        apt_indicators = ['apt', 'advanced persistent threat', 'nation-state', 'state-sponsored']
        text_to_check = (self.name + ' ' + self.description + ' ' + ' '.join(self.aliases)).lower()
        return any(indicator in text_to_check for indicator in apt_indicators)
    
    def get_primary_target_sector(self) -> str:
        """Get the primary target sector"""
        if self.targets:
            return self.targets[0]
        return 'Unknown'


class SecurityTool:
    """
    Represents a security tool or technique used by threat actors
    """
    
    def __init__(self,
                 id: str,
                 name: str,
                 description: str,
                 category: str,
                 platforms: List[str] = None,
                 used_by: List[str] = None,
                 techniques: List[str] = None,
                 **kwargs):
        
        self.id = id
        self.name = name
        self.description = description
        self.category = category
        self.platforms = platforms or []
        self.used_by = used_by or []  # Threat actors that use this tool
        self.techniques = techniques or []  # MITRE ATT&CK techniques
        
        # Additional fields
        self.detection = kwargs.get('detection', '')
        self.mitigation = kwargs.get('mitigation', '')
        self.is_legitimate = kwargs.get('is_legitimate', False)  # Dual-use tool
        self.availability = kwargs.get('availability', 'Unknown')  # Free, Commercial, etc.
        self.references = kwargs.get('references', [])
        self.aliases = kwargs.get('aliases', [])
    
    def to_dict(self) -> Dict:
        """Convert security tool to dictionary format"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'platforms': self.platforms,
            'used_by': self.used_by,
            'techniques': self.techniques,
            'detection': self.detection,
            'mitigation': self.mitigation,
            'is_legitimate': self.is_legitimate,
            'availability': self.availability,
            'references': self.references,
            'aliases': self.aliases
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'SecurityTool':
        """Create SecurityTool instance from dictionary"""
        return cls(**data)
    
    def is_dual_use(self) -> bool:
        """Check if this is a dual-use (legitimate + malicious) tool"""
        return self.is_legitimate or 'dual-use' in self.category.lower()
    
    def get_risk_level(self) -> str:
        """Assess risk level based on usage and legitimacy"""
        if not self.is_legitimate and len(self.used_by) > 5:
            return 'High'
        elif self.is_legitimate and len(self.used_by) > 10:
            return 'Medium'
        elif len(self.used_by) > 2:
            return 'Medium'
        else:
            return 'Low'


class ThreatIntelligenceDatabase:
    """
    Container class for managing collections of threat intelligence data
    """
    
    def __init__(self):
        self.threats: List[ThreatData] = []
        self.actors: List[ThreatActor] = []
        self.tools: List[SecurityTool] = []
        self.last_updated = datetime.now().isoformat()
    
    def add_threat(self, threat: ThreatData):
        """Add a threat to the database"""
        self.threats.append(threat)
        self._update_timestamp()
    
    def add_actor(self, actor: ThreatActor):
        """Add a threat actor to the database"""
        self.actors.append(actor)
        self._update_timestamp()
    
    def add_tool(self, tool: SecurityTool):
        """Add a security tool to the database"""
        self.tools.append(tool)
        self._update_timestamp()
    
    def get_recent_threats(self, days: int = 7) -> List[ThreatData]:
        """Get threats from the last N days"""
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_threats = []
        
        for threat in self.threats:
            try:
                threat_date = datetime.fromisoformat(threat.date.replace('Z', '+00:00'))
                if threat_date >= cutoff_date:
                    recent_threats.append(threat)
            except:
                continue
        
        return sorted(recent_threats, key=lambda x: x.date, reverse=True)
    
    def get_threats_by_severity(self, severity: str) -> List[ThreatData]:
        """Get threats filtered by severity level"""
        return [t for t in self.threats if t.severity.lower() == severity.lower()]
    
    def search_threats(self, query: str) -> List[ThreatData]:
        """Search threats by name, description, or tags"""
        query = query.lower()
        results = []
        
        for threat in self.threats:
            if (query in threat.name.lower() or 
                query in threat.description.lower() or
                any(query in tag.lower() for tag in threat.tags)):
                results.append(threat)
        
        return results
    
    def get_stats(self) -> Dict:
        """Get database statistics"""
        return {
            'total_threats': len(self.threats),
            'total_actors': len(self.actors),
            'total_tools': len(self.tools),
            'recent_threats': len(self.get_recent_threats()),
            'critical_threats': len(self.get_threats_by_severity('Critical')),
            'high_threats': len(self.get_threats_by_severity('High')),
            'last_updated': self.last_updated
        }
    
    def _update_timestamp(self):
        """Update the last updated timestamp"""
        self.last_updated = datetime.now().isoformat()
    
    def to_json(self) -> str:
        """Export database to JSON format"""
        data = {
            'threats': [threat.to_dict() for threat in self.threats],
            'actors': [actor.to_dict() for actor in self.actors],
            'tools': [tool.to_dict() for tool in self.tools],
            'last_updated': self.last_updated
        }
        return json.dumps(data, indent=2, default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ThreatIntelligenceDatabase':
        """Create database from JSON format"""
        data = json.loads(json_str)
        db = cls()
        
        # Load threats
        for threat_data in data.get('threats', []):
            db.threats.append(ThreatData.from_dict(threat_data))
        
        # Load actors
        for actor_data in data.get('actors', []):
            db.actors.append(ThreatActor.from_dict(actor_data))
        
        # Load tools
        for tool_data in data.get('tools', []):
            db.tools.append(SecurityTool.from_dict(tool_data))
        
        db.last_updated = data.get('last_updated', datetime.now().isoformat())
        return db