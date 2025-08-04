import feedparser
from datetime import datetime
from bs4 import BeautifulSoup
from config import Config

class RSSService:
    """Service for fetching cybersecurity news from RSS feeds"""
    
    def __init__(self):
        self.feeds = Config.RSS_FEEDS
        
    def fetch_all_feeds(self):
        """Fetch articles from all configured RSS feeds"""
        all_articles = []
        
        for feed_config in self.feeds:
            articles = self.fetch_feed(feed_config)
            if articles:
                all_articles.extend(articles)
        
        # Sort by date (newest first)
        all_articles.sort(key=lambda x: x.get('published_parsed', ''), reverse=True)
        
        return all_articles[:100]  # Limit to 100 most recent articles
    
    def fetch_feed(self, feed_config):
        """Fetch articles from a single RSS feed"""
        try:
            print(f"Fetching RSS feed: {feed_config['name']}")
            
            feed = feedparser.parse(feed_config['url'])
            
            if feed.bozo:
                print(f"Warning: RSS feed {feed_config['name']} may have parsing issues")
            
            articles = []
            for entry in feed.entries[:20]:  # Limit to 20 articles per feed
                # Clean up description
                description = entry.get('description', '') or entry.get('summary', '')
                if description:
                    soup = BeautifulSoup(description, 'html.parser')
                    description = soup.get_text().strip()[:500]  # Limit description length
                
                article = {
                    'id': entry.get('id', entry.get('link', '')),
                    'title': entry.get('title', ''),
                    'description': description,
                    'link': entry.get('link', ''),
                    'published': entry.get('published', ''),
                    'published_parsed': entry.get('published_parsed'),
                    'author': entry.get('author', ''),
                    'source': feed_config['name'],
                    'category': feed_config['category'],
                    'date': datetime.now().isoformat(),
                    'tags': self._extract_tags(entry.get('title', '') + ' ' + description),
                    'threat_level': self._assess_threat_level(entry.get('title', '') + ' ' + description)
                }
                articles.append(article)
            
            print(f"Fetched {len(articles)} articles from {feed_config['name']}")
            return articles
            
        except Exception as e:
            print(f"Error fetching RSS feed {feed_config['name']}: {e}")
            return None
    
    def _extract_tags(self, text):
        """Extract relevant cybersecurity tags from text"""
        text_lower = text.lower()
        tags = []
        
        # Threat types
        threat_keywords = {
            'malware': ['malware', 'trojan', 'virus', 'worm', 'spyware', 'adware'],
            'ransomware': ['ransomware', 'crypto-locker', 'lock-bit', 'conti'],
            'phishing': ['phishing', 'spear phishing', 'email scam'],
            'apt': ['apt', 'advanced persistent threat', 'nation-state'],
            'vulnerability': ['vulnerability', 'cve-', 'zero-day', 'exploit'],
            'ddos': ['ddos', 'denial of service', 'botnet'],
            'data-breach': ['data breach', 'leak', 'exposed database'],
            'insider-threat': ['insider threat', 'rogue employee'],
            'supply-chain': ['supply chain', 'third-party', 'vendor'],
            'iot': ['iot', 'internet of things', 'smart device'],
            'cloud': ['cloud', 'aws', 'azure', 'gcp', 'saas'],
            'mobile': ['mobile', 'android', 'ios', 'smartphone'],
            'critical-infrastructure': ['scada', 'ics', 'infrastructure', 'power grid']
        }
        
        for tag, keywords in threat_keywords.items():
            if any(keyword in text_lower for keyword in keywords):
                tags.append(tag)
        
        return tags
    
    def _assess_threat_level(self, text):
        """Assess threat level based on keywords"""
        text_lower = text.lower()
        
        critical_keywords = ['critical', 'zero-day', 'actively exploited', 'widespread', 'emergency']
        high_keywords = ['high', 'severe', 'dangerous', 'urgent', 'major breach']
        medium_keywords = ['medium', 'moderate', 'warning', 'vulnerability']
        
        if any(keyword in text_lower for keyword in critical_keywords):
            return 'Critical'
        elif any(keyword in text_lower for keyword in high_keywords):
            return 'High'
        elif any(keyword in text_lower for keyword in medium_keywords):
            return 'Medium'
        else:
            return 'Low'