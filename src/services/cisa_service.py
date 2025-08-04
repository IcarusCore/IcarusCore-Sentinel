import requests
import feedparser
from datetime import datetime
from bs4 import BeautifulSoup
from config import Config

class CISAService:
    """Service for fetching CISA (Cybersecurity and Infrastructure Security Agency) alerts"""
    
    def __init__(self):
        self.rss_url = Config.CISA_ALERTS_RSS
        
    def fetch_alerts(self):
        """Fetch CISA cybersecurity alerts from RSS feed"""
        try:
            print("Fetching CISA alerts...")
            
            # Parse RSS feed
            feed = feedparser.parse(self.rss_url)
            
            if feed.bozo:
                print("Warning: RSS feed may have parsing issues")
            
            alerts = []
            for entry in feed.entries[:50]:  # Limit to recent 50 alerts
                # Clean up description
                description = entry.get('description', '')
                if description:
                    soup = BeautifulSoup(description, 'html.parser')
                    description = soup.get_text().strip()
                
                alert = {
                    'id': entry.get('id', entry.get('link', '')),
                    'title': entry.get('title', ''),
                    'description': description,
                    'link': entry.get('link', ''),
                    'published': entry.get('published', ''),
                    'date': datetime.now().isoformat(),
                    'source': 'CISA',
                    'severity': self._extract_severity(entry.get('title', '')),
                    'tags': self._extract_tags(entry.get('title', '') + ' ' + description)
                }
                alerts.append(alert)
            
            print(f"Fetched {len(alerts)} CISA alerts")
            return alerts
            
        except Exception as e:
            print(f"Error fetching CISA alerts: {e}")
            return None
    
    def _extract_severity(self, title):
        """Extract severity level from alert title"""
        title_lower = title.lower()
        if 'critical' in title_lower:
            return 'Critical'
        elif 'high' in title_lower:
            return 'High'
        elif 'medium' in title_lower:
            return 'Medium'
        elif 'low' in title_lower:
            return 'Low'
        else:
            return 'Unknown'
    
    def _extract_tags(self, text):
        """Extract relevant tags from text"""
        text_lower = text.lower()
        tags = []
        
        # Common vulnerability types
        if 'ransomware' in text_lower:
            tags.append('ransomware')
        if 'phishing' in text_lower:
            tags.append('phishing')
        if 'malware' in text_lower:
            tags.append('malware')
        if 'vulnerability' in text_lower or 'cve' in text_lower:
            tags.append('vulnerability')
        if 'apt' in text_lower or 'advanced persistent threat' in text_lower:
            tags.append('apt')
        if 'zero-day' in text_lower or 'zero day' in text_lower:
            tags.append('zero-day')
        if 'supply chain' in text_lower:
            tags.append('supply-chain')
        if 'ddos' in text_lower:
            tags.append('ddos')
        
        return tags