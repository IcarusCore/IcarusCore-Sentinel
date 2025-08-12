import os
from datetime import timedelta
import secrets

class Config:
    """
    Configuration class that reads from environment variables
    Perfect for Docker/Unraid deployment
    """
    
    # Flask settings - Read from environment with defaults
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    FLASK_ENV = os.environ.get('FLASK_ENV', 'production')
    
    # Server settings
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', '5000'))
    
    # Data refresh intervals (in hours) - Configurable via environment
    MITRE_REFRESH_INTERVAL = int(os.environ.get('MITRE_REFRESH_INTERVAL', '24'))
    OTX_REFRESH_INTERVAL = int(os.environ.get('OTX_REFRESH_INTERVAL', '6'))
    CISA_REFRESH_INTERVAL = int(os.environ.get('CISA_REFRESH_INTERVAL', '4'))
    RSS_REFRESH_INTERVAL = int(os.environ.get('RSS_REFRESH_INTERVAL', '2'))
    
    # API Keys - Read from environment (Unraid will set these)
    OTX_API_KEY = os.environ.get('OTX_API_KEY', '')
    
    # Optional future API keys
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    
    # Data sources URLs
    MITRE_ATTACK_URL = os.environ.get('MITRE_ATTACK_URL', 
        'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json')
    CISA_ALERTS_RSS = os.environ.get('CISA_ALERTS_RSS', 
        'https://www.cisa.gov/cybersecurity-advisories/all.xml')
    
    # RSS Feeds configuration
    RSS_FEEDS = [
        {
            'name': 'BleepingComputer',
            'url': os.environ.get('RSS_BLEEPING_COMPUTER', 'https://www.bleepingcomputer.com/feed/'),
            'category': 'news'
        },
        {
            'name': 'Krebs on Security',
            'url': os.environ.get('RSS_KREBS', 'https://krebsonsecurity.com/feed/'),
            'category': 'news'
        },
        {
            'name': 'The Hacker News',
            'url': os.environ.get('RSS_HACKER_NEWS', 'https://feeds.feedburner.com/TheHackersNews'),
            'category': 'news'
        }
    ]
    
    # File paths - Use Docker volumes
    DATA_DIR = os.environ.get('DATA_DIR', '/app/data')
    LOGS_DIR = os.environ.get('LOGS_DIR', '/app/logs')
    
    # Ensure directories exist
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    
    # Data files
    THREATS_FILE = os.path.join(DATA_DIR, 'threats.json')
    ACTORS_FILE = os.path.join(DATA_DIR, 'actors.json')
    TOOLS_FILE = os.path.join(DATA_DIR, 'tools.json')
    
    # Pagination
    ITEMS_PER_PAGE = int(os.environ.get('ITEMS_PER_PAGE', '20'))
    
    # Cache settings
    CACHE_TIMEOUT = timedelta(hours=int(os.environ.get('CACHE_TIMEOUT_HOURS', '1')))
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.path.join(LOGS_DIR, 'threatintel.log')
    
    # Timezone
    TIMEZONE = os.environ.get('TZ', 'UTC')
    
    @classmethod
    def validate_config(cls):
        """Validate configuration and show warnings"""
        warnings = []
        
        if not cls.OTX_API_KEY:
            warnings.append("OTX_API_KEY not set - AlienVault OTX integration disabled")
        
        if cls.SECRET_KEY == 'your-secret-key-here-change-in-production':
            warnings.append("Using default SECRET_KEY - Please set a secure key in production")
        
        if cls.DEBUG and cls.FLASK_ENV == 'production':
            warnings.append("DEBUG mode enabled in production - This is a security risk")
        
        return warnings
    
    @classmethod
    def print_config(cls):
        """Print current configuration (for debugging)"""
        print("=== Threat Intelligence Dashboard Configuration ===")
        print(f"Environment: {cls.FLASK_ENV}")
        print(f"Debug Mode: {cls.DEBUG}")
        print(f"Host: {cls.HOST}:{cls.PORT}")
        print(f"Data Directory: {cls.DATA_DIR}")
        print(f"Logs Directory: {cls.LOGS_DIR}")
        print(f"OTX API Key: {'[SET]' if cls.OTX_API_KEY else '[NOT SET]'}")
        print(f"Refresh Intervals:")
        print(f"  - MITRE: {cls.MITRE_REFRESH_INTERVAL} hours")
        print(f"  - OTX: {cls.OTX_REFRESH_INTERVAL} hours")
        print(f"  - CISA: {cls.CISA_REFRESH_INTERVAL} hours")
        print(f"  - RSS: {cls.RSS_REFRESH_INTERVAL} hours")
        print(f"Timezone: {cls.TIMEZONE}")
        print("=" * 50)