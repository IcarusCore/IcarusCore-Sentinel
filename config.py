import os
from datetime import timedelta

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    # Data refresh intervals (in hours)
    MITRE_REFRESH_INTERVAL = 24  # Daily
    OTX_REFRESH_INTERVAL = 6     # Every 6 hours
    CISA_REFRESH_INTERVAL = 4    # Every 4 hours
    RSS_REFRESH_INTERVAL = 2     # Every 2 hours
    
    # API Keys (set these as environment variables)
    OTX_API_KEY = os.environ.get('OTX_API_KEY', '')
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
    
    # Data sources URLs
    MITRE_ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    CISA_ALERTS_RSS = 'https://www.cisa.gov/cybersecurity-advisories/all.xml'
    
    # RSS Feeds for security news
    RSS_FEEDS = [
        {
            'name': 'BleepingComputer',
            'url': 'https://www.bleepingcomputer.com/feed/',
            'category': 'news'
        },
        {
            'name': 'Krebs on Security',
            'url': 'https://krebsonsecurity.com/feed/',
            'category': 'news'
        },
        {
            'name': 'The Hacker News',
            'url': 'https://feeds.feedburner.com/TheHackersNews',
            'category': 'news'
        }
    ]
    
    # File paths
    DATA_DIR = 'data'
    THREATS_FILE = os.path.join(DATA_DIR, 'threats.json')
    ACTORS_FILE = os.path.join(DATA_DIR, 'actors.json')
    TOOLS_FILE = os.path.join(DATA_DIR, 'tools.json')
    
    # Pagination
    ITEMS_PER_PAGE = 20
    
    # Cache settings
    CACHE_TIMEOUT = timedelta(hours=1)