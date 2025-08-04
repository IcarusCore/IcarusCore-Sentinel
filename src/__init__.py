"""
Threat Intelligence Dashboard - Core Package

This package contains the core functionality for the threat intelligence
aggregation and processing system.
"""

__version__ = '1.0.0'
__author__ = 'Threat Intel Dashboard Team'

# Import main components for easy access
from .services.mitre_service import MitreService
from .services.cisa_service import CISAService
from .services.rss_service import RSSService
from .services.otx_service import OTXService
from .utils.data_processor import DataProcessor
from .utils.helpers import (
    format_date, 
    truncate_text, 
    get_severity_color,
    calculate_threat_score,
    get_attack_phase_description
)

__all__ = [
    'MitreService',
    'CISAService', 
    'RSSService',
    'OTXService',
    'DataProcessor',
    'format_date',
    'truncate_text',
    'get_severity_color',
    'calculate_threat_score',
    'get_attack_phase_description'
]