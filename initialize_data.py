#!/usr/bin/env python3
"""
Initialize the threat intelligence database with sample data
Run this script to populate the JSON files with the data we created
"""

import os
import json
from datetime import datetime

def create_data_directory():
    """Create the data directory if it doesn't exist"""
    if not os.path.exists('data'):
        os.makedirs('data')
        print("Created data directory")

def initialize_data():
    """Initialize all JSON data files"""
    
    # Sample threats data
    threats_data = [
        {
            "id": "T1566.001",
            "name": "Spearphishing Attachment",
            "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.",
            "tactic": "initial-access",
            "techniques": ["T1566.001"],
            "platforms": ["Linux", "macOS", "Windows"],
            "severity": "High",
            "source": "MITRE ATT&CK",
            "date": datetime.now().isoformat(),
            "tags": ["email", "attachment", "initial-access", "phishing"]
        },
        {
            "id": "T1059.001", 
            "name": "PowerShell",
            "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "tactic": "execution",
            "techniques": ["T1059.001"],
            "platforms": ["Windows"],
            "severity": "Medium",
            "source": "MITRE ATT&CK", 
            "date": datetime.now().isoformat(),
            "tags": ["powershell", "execution", "windows", "scripting"]
        },
        {
            "id": "CISA-2024-001",
            "name": "Critical Infrastructure Alert",
            "description": "CISA alert regarding increased ransomware activity targeting critical infrastructure.",
            "tactic": "Alert",
            "techniques": [],
            "platforms": ["Windows", "Linux"],
            "severity": "Critical",
            "source": "CISA",
            "date": datetime.now().isoformat(),
            "tags": ["ransomware", "critical-infrastructure", "alert", "cisa"]
        }
    ]
    
    # Sample actors data
    actors_data = [
        {
            "id": "apt28",
            "name": "APT28",
            "description": "Russian military intelligence cyber unit, also known as Fancy Bear.",
            "country": "Russia",
            "aliases": ["Fancy Bear", "Pawn Storm", "Sofacy"],
            "targets": ["Government", "Military", "Media"],
            "techniques": ["Zero-day Exploits", "Spear Phishing", "Credential Harvesting"],
            "tools": ["X-Agent", "Komplex", "CHOPSTICK"],
            "active_since": "2007",
            "sophistication": "High",
            "attribution_confidence": "High",
            "source": "MITRE ATT&CK"
        },
        {
            "id": "apt29",
            "name": "APT29", 
            "description": "Russian intelligence service group, also known as Cozy Bear.",
            "country": "Russia",
            "aliases": ["Cozy Bear", "CozyDuke", "The Dukes"],
            "targets": ["Government", "Healthcare", "Technology"],
            "techniques": ["Supply Chain Attacks", "Living off the Land", "Steganography"],
            "tools": ["HAMMERTOSS", "POWERDUKE", "COZYDUKE"],
            "active_since": "2008",
            "sophistication": "High",
            "attribution_confidence": "High",
            "source": "MITRE ATT&CK"
        },
        {
            "id": "lazarus",
            "name": "Lazarus Group",
            "description": "North Korean state-sponsored group behind major cyber attacks.",
            "country": "North Korea",
            "aliases": ["HIDDEN COBRA", "Guardians of Peace"],
            "targets": ["Financial", "Cryptocurrency", "Entertainment"],
            "techniques": ["Destructive Malware", "Financial Theft", "Ransomware"],
            "tools": ["WannaCry", "FALLCHILL", "HOPLIGHT"],
            "active_since": "2009", 
            "sophistication": "High",
            "attribution_confidence": "High",
            "source": "MITRE ATT&CK"
        }
    ]
    
    # Sample tools data
    tools_data = [
        {
            "id": "powershell",
            "name": "PowerShell",
            "description": "Command-line shell and scripting language often abused by attackers",
            "category": "Dual-use Tool",
            "platforms": ["Windows"],
            "used_by": ["APT28", "APT29", "FIN7"],
            "techniques": ["T1059.001"],
            "detection": "Monitor PowerShell execution and command-line arguments",
            "mitigation": "Enable PowerShell logging and restrict execution policies",
            "is_legitimate": True,
            "availability": "Built-in",
            "risk_level": "High"
        },
        {
            "id": "mimikatz",
            "name": "Mimikatz",
            "description": "Tool for extracting passwords and authentication tokens from Windows",
            "category": "Credential Access",
            "platforms": ["Windows"],
            "used_by": ["Multiple APT groups"],
            "techniques": ["T1003.001", "T1558"],
            "detection": "Monitor for LSASS access and credential dumping activities",
            "mitigation": "Implement credential guard and limit admin privileges",
            "is_legitimate": True,
            "availability": "Free",
            "risk_level": "Critical"
        },
        {
            "id": "cobalt-strike",
            "name": "Cobalt Strike", 
            "description": "Commercial penetration testing tool frequently used in attacks",
            "category": "Command and Control",
            "platforms": ["Windows", "Linux", "macOS"],
            "used_by": ["Ransomware groups", "APT groups"],
            "techniques": ["T1071", "T1055"],
            "detection": "Monitor for beacon communications and process injection",
            "mitigation": "Block known C2 domains and monitor network traffic",
            "is_legitimate": True,
            "availability": "Commercial",
            "risk_level": "High"
        },
        {
            "id": "nmap",
            "name": "Nmap",
            "description": "Network discovery and security auditing tool",
            "category": "Network",
            "platforms": ["Windows", "Linux", "macOS"],
            "used_by": ["Security professionals", "Threat actors"],
            "techniques": ["T1046"],
            "detection": "Monitor for network scanning activities",
            "mitigation": "Implement network monitoring and intrusion detection",
            "is_legitimate": True,
            "availability": "Free",
            "risk_level": "Medium"
        }
    ]
    
    # Write data to files
    create_data_directory()
    
    with open('data/threats.json', 'w') as f:
        json.dump(threats_data, f, indent=2)
    print("Created data/threats.json")
    
    with open('data/actors.json', 'w') as f:
        json.dump(actors_data, f, indent=2)
    print("Created data/actors.json")
        
    with open('data/tools.json', 'w') as f:
        json.dump(tools_data, f, indent=2)
    print("Created data/tools.json")
    
    print("\nData initialization complete!")
    print("You can now run 'python app.py' to start the application.")

if __name__ == "__main__":
    initialize_data()