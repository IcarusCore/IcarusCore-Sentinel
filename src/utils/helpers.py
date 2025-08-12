from datetime import datetime
import re

def format_date(date_string):
    """Format date string for display"""
    try:
        if not date_string:
            return 'Unknown'
        
        # Handle ISO format
        if 'T' in date_string:
            dt = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M')
        
        # Handle other common formats
        try:
            dt = datetime.strptime(date_string, '%Y-%m-%d')
            return dt.strftime('%Y-%m-%d')
        except:
            return date_string
            
    except Exception:
        return 'Unknown'

def truncate_text(text, length=150):
    """Truncate text to specified length with ellipsis"""
    if not text:
        return ''
    
    if len(text) <= length:
        return text
    
    return text[:length-3] + '...'

def clean_html(text):
    """Remove HTML tags from text"""
    if not text:
        return ''
    
    # Remove HTML tags
    clean = re.compile('<.*?>')
    return re.sub(clean, '', text)

def extract_cve_ids(text):
    """Extract CVE IDs from text"""
    if not text:
        return []
    
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    return re.findall(cve_pattern, text, re.IGNORECASE)

def get_severity_color(severity):
    """Get color class for severity level"""
    severity_colors = {
        'Critical': 'danger',
        'High': 'warning',
        'Medium': 'info',
        'Low': 'secondary',
        'Unknown': 'light'
    }
    return severity_colors.get(severity, 'light')

def get_mitre_technique_url(technique_id):
    """Generate MITRE ATT&CK technique URL with correct format for sub-techniques"""
    if not technique_id or not technique_id.startswith('T'):
        return None
    
    if '.' in technique_id:
        # Sub-technique: T1546.012 -> https://attack.mitre.org/techniques/T1546/012/
        main_technique, sub_technique = technique_id.split('.', 1)
        return f"https://attack.mitre.org/techniques/{main_technique}/{sub_technique}/"
    else:
        # Main technique: T1546 -> https://attack.mitre.org/techniques/T1546/
        return f"https://attack.mitre.org/techniques/{technique_id}/"

def sanitize_filename(filename):
    """Sanitize filename for safe file operations"""
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    return filename[:255]  # Limit length

def calculate_threat_score(threat):
    """Calculate a numerical threat score for prioritization"""
    score = 0
    
    # Severity scoring
    severity_scores = {
        'Critical': 10,
        'High': 7,
        'Medium': 4,
        'Low': 1,
        'Unknown': 2
    }
    
    score += severity_scores.get(threat.get('severity', 'Unknown'), 2)
    
    # Source reliability scoring
    source_scores = {
        'MITRE ATT&CK': 8,
        'CISA': 9,
        'AlienVault OTX': 6,
        'BleepingComputer': 5,
        'Krebs on Security': 6,
        'The Hacker News': 4
    }
    
    score += source_scores.get(threat.get('source', ''), 3)
    
    # Recency scoring (more recent = higher score)
    try:
        threat_date = datetime.fromisoformat(threat.get('date', ''))
        days_old = (datetime.now() - threat_date).days
        
        if days_old <= 1:
            score += 5
        elif days_old <= 7:
            score += 3
        elif days_old <= 30:
            score += 1
    except:
        pass
    
    return score

def get_attack_phase_description(tactic):
    """Get human-readable description for MITRE ATT&CK tactics"""
    descriptions = {
        'initial-access': 'Getting into your network',
        'execution': 'Running malicious code',
        'persistence': 'Maintaining foothold',
        'privilege-escalation': 'Gaining higher-level permissions',
        'defense-evasion': 'Avoiding detection',
        'credential-access': 'Stealing account details',
        'discovery': 'Figuring out your environment',
        'lateral-movement': 'Moving through your network',
        'collection': 'Gathering data of interest',
        'command-and-control': 'Communicating with outside systems',
        'exfiltration': 'Stealing data',
        'impact': 'Destroying or disrupting systems'
    }
    
    return descriptions.get(tactic.lower(), tactic)

def format_tags(tags):
    """Format tags for display"""
    if not tags:
        return []
    
    # Clean and format tags
    formatted_tags = []
    for tag in tags:
        if isinstance(tag, str):
            # Clean tag
            clean_tag = tag.strip().lower()
            # Capitalize first letter
            clean_tag = clean_tag.replace('-', ' ').replace('_', ' ')
            clean_tag = ' '.join(word.capitalize() for word in clean_tag.split())
            
            if clean_tag and clean_tag not in formatted_tags:
                formatted_tags.append(clean_tag)
    
    return formatted_tags[:10]  # Limit to 10 tags