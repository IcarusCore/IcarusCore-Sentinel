from flask import Flask, render_template, jsonify, request
from datetime import datetime, timedelta
import json
import os
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

# Import our custom modules (Shodan service removed)
from src.services.mitre_service import MitreService
from src.services.otx_service import OTXService
from src.services.cisa_service import CISAService
from src.services.rss_service import RSSService
from src.utils.data_processor import DataProcessor
from src.utils.helpers import format_date, truncate_text
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Initialize services (Shodan service removed)
mitre_service = MitreService()
otx_service = OTXService()
cisa_service = CISAService()
rss_service = RSSService()
data_processor = DataProcessor()

# Template filters
app.jinja_env.filters['format_date'] = format_date
app.jinja_env.filters['truncate_text'] = truncate_text

# Add template globals
@app.template_global()
def get_current_time():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def update_threat_data():
    """Update threat intelligence data from all sources (Shodan removed)"""
    print(f"[{datetime.now()}] Starting threat data update...")
    
    try:
        # Update MITRE ATT&CK data
        mitre_data = mitre_service.fetch_attack_data()
        if mitre_data:
            data_processor.process_mitre_data(mitre_data)
            print("✓ MITRE ATT&CK data updated")
        
        # Update CISA alerts
        cisa_data = cisa_service.fetch_alerts()
        if cisa_data:
            data_processor.process_cisa_data(cisa_data)
            print("✓ CISA alerts updated")
        
        # Update RSS feeds
        rss_data = rss_service.fetch_all_feeds()
        if rss_data:
            data_processor.process_rss_data(rss_data)
            print("✓ RSS feeds updated")
        
        # Update OTX data (if API key is available)
        if app.config['OTX_API_KEY']:
            otx_data = otx_service.fetch_pulses()
            if otx_data:
                data_processor.process_otx_data(otx_data)
                print("✓ OTX data updated")
        
        print(f"[{datetime.now()}] Threat data update completed")
        
    except Exception as e:
        print(f"Error updating threat data: {e}")

@app.route('/')
def index():
    """Homepage with dashboard overview"""
    try:
        # Load recent threats
        with open(app.config['THREATS_FILE'], 'r') as f:
            threats = json.load(f)
        
        # Get latest items for dashboard
        recent_threats = sorted(threats, key=lambda x: x.get('date', ''), reverse=True)[:6]
        
        # Load threat actors
        actors = []
        if os.path.exists(app.config['ACTORS_FILE']):
            with open(app.config['ACTORS_FILE'], 'r') as f:
                actors = json.load(f)[:6]
        
        # Load tools
        tools = []
        if os.path.exists(app.config['TOOLS_FILE']):
            with open(app.config['TOOLS_FILE'], 'r') as f:
                tools = json.load(f)[:6]
        
        # Stats
        stats = {
            'total_threats': len(threats),
            'total_actors': len(actors) if actors else 0,
            'total_tools': len(tools) if tools else 0,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return render_template('index.html', 
                             recent_threats=recent_threats,
                             actors=actors,
                             tools=tools,
                             stats=stats)
    except Exception as e:
        print(f"Error loading dashboard: {e}")
        return render_template('index.html', 
                             recent_threats=[],
                             actors=[],
                             tools=[],
                             stats={})

@app.route('/ttps')
def ttps():
    """TTPs (Tactics, Techniques, and Procedures) page"""
    page = request.args.get('page', 1, type=int)
    tactic_filter = request.args.get('tactic', '')
    search_query = request.args.get('search', '')
    
    try:
        with open(app.config['THREATS_FILE'], 'r') as f:
            all_threats = json.load(f)
        
        # Filter threats
        filtered_threats = []
        for threat in all_threats:
            if tactic_filter and threat.get('tactic', '').lower() != tactic_filter.lower():
                continue
            if search_query and search_query.lower() not in threat.get('name', '').lower():
                continue
            filtered_threats.append(threat)
        
        # Pagination
        per_page = app.config['ITEMS_PER_PAGE']
        start = (page - 1) * per_page
        end = start + per_page
        threats = filtered_threats[start:end]
        
        # Get unique tactics for filter
        tactics = list(set([t.get('tactic', 'Unknown') for t in all_threats if t.get('tactic')]))
        tactics.sort()
        
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': len(filtered_threats),
            'pages': (len(filtered_threats) + per_page - 1) // per_page
        }
        
        return render_template('ttps.html', 
                             threats=threats,
                             tactics=tactics,
                             current_tactic=tactic_filter,
                             search_query=search_query,
                             pagination=pagination)
    except Exception as e:
        print(f"Error loading TTPs: {e}")
        return render_template('ttps.html', threats=[], tactics=[], pagination={})

def calculate_actor_statistics(actors):
    """Calculate comprehensive statistics for actors"""
    if not actors:
        return {
            'total_actors': 0,
            'apt_groups': 0,
            'countries': 0,
            'high_sophistication': 0,
            'nation_state_groups': 0,
            'active_groups': 0,
            'by_country': {},
            'by_sophistication': {'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0},
            'by_confidence': {'High': 0, 'Medium': 0, 'Low': 0},
            'top_targets': []
        }
    
    stats = {
        'total_actors': len(actors),
        'apt_groups': 0,
        'countries': 0,
        'high_sophistication': 0,
        'nation_state_groups': 0,
        'active_groups': 0,
        'by_country': {},
        'by_sophistication': {'High': 0, 'Medium': 0, 'Low': 0, 'Unknown': 0},
        'by_confidence': {'High': 0, 'Medium': 0, 'Low': 0},
        'top_targets': []
    }
    
    countries = set()
    all_targets = []
    
    for actor in actors:
        # Count APT groups
        if 'APT' in actor.get('name', '').upper():
            stats['apt_groups'] += 1
        
        # Count nation-state groups
        if actor.get('country') and actor.get('country') != '':
            stats['nation_state_groups'] += 1
            countries.add(actor['country'])
            
            # Count by country
            country = actor['country']
            stats['by_country'][country] = stats['by_country'].get(country, 0) + 1
        
        # Count by sophistication
        sophistication = actor.get('sophistication', 'Unknown')
        if sophistication in stats['by_sophistication']:
            stats['by_sophistication'][sophistication] += 1
        else:
            stats['by_sophistication']['Unknown'] += 1
            
        if sophistication == 'High':
            stats['high_sophistication'] += 1
        
        # Count by attribution confidence
        confidence = actor.get('attribution_confidence', 'Medium')
        if confidence in stats['by_confidence']:
            stats['by_confidence'][confidence] += 1
        
        # Collect targets
        if actor.get('targets'):
            all_targets.extend(actor['targets'])
        
        # Count active groups (assume all loaded actors are active)
        stats['active_groups'] += 1
    
    # Calculate unique countries
    stats['countries'] = len(countries)
    
    # Calculate top targets
    if all_targets:
        from collections import Counter
        target_counts = Counter(all_targets)
        stats['top_targets'] = target_counts.most_common(5)
    
    return stats

@app.route('/actors')
def actors():
    """Threat actors page"""
    try:
        actors = []
        if os.path.exists(app.config['ACTORS_FILE']):
            with open(app.config['ACTORS_FILE'], 'r') as f:
                actors = json.load(f)
        
        # Ensure each actor has required fields
        for actor in actors:
            if 'aliases' not in actor:
                actor['aliases'] = []
            if 'targets' not in actor:
                actor['targets'] = []
            if 'techniques' not in actor:
                actor['techniques'] = []
            if 'tools' not in actor:
                actor['tools'] = []
            if 'sophistication' not in actor:
                actor['sophistication'] = 'Unknown'
            if 'attribution_confidence' not in actor:
                actor['attribution_confidence'] = 'Medium'
            if 'country' not in actor:
                actor['country'] = ''
            if 'name' not in actor:
                actor['name'] = 'Unknown Actor'
        
        # Calculate actor statistics
        actor_stats = calculate_actor_statistics(actors)
        
        return render_template('actors.html', actors=actors, actor_stats=actor_stats)
        
    except Exception as e:
        print(f"Error loading actors: {e}")
        # Return empty data with basic stats to prevent template errors
        empty_stats = {
            'total_actors': 0,
            'apt_groups': 0,
            'countries': 0,
            'high_sophistication': 0
        }
        return render_template('actors.html', actors=[], actor_stats=empty_stats)

@app.route('/tools')
def tools():
    """Tools and techniques page"""
    try:
        tools = []
        if os.path.exists(app.config['TOOLS_FILE']):
            with open(app.config['TOOLS_FILE'], 'r') as f:
                tools = json.load(f)
        
        # Add get_risk_level method simulation for templates
        for tool in tools:
            if 'risk_level' not in tool:
                # Simple risk assessment
                used_by_count = len(tool.get('used_by', []))
                if used_by_count > 5:
                    tool['risk_level'] = 'High'
                elif used_by_count > 2:
                    tool['risk_level'] = 'Medium'
                else:
                    tool['risk_level'] = 'Low'
        
        return render_template('tools.html', tools=tools)
    except Exception as e:
        print(f"Error loading tools: {e}")
        return render_template('tools.html', tools=[])

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/api/refresh')
def api_refresh():
    """API endpoint to manually refresh data"""
    try:
        update_threat_data()
        return jsonify({'status': 'success', 'message': 'Data refreshed successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/stats')
def api_stats():
    """API endpoint to get current statistics"""
    try:
        with open(app.config['THREATS_FILE'], 'r') as f:
            threats = json.load(f)
        
        actors = []
        if os.path.exists(app.config['ACTORS_FILE']):
            with open(app.config['ACTORS_FILE'], 'r') as f:
                actors = json.load(f)
        
        tools = []
        if os.path.exists(app.config['TOOLS_FILE']):
            with open(app.config['TOOLS_FILE'], 'r') as f:
                tools = json.load(f)
        
        return jsonify({
            'total_threats': len(threats),
            'total_actors': len(actors),
            'total_tools': len(tools),
            'last_updated': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/actors/stats')
def api_actors_stats():
    """API endpoint to get actor statistics"""
    try:
        actors = []
        if os.path.exists(app.config['ACTORS_FILE']):
            with open(app.config['ACTORS_FILE'], 'r') as f:
                actors = json.load(f)
        
        stats = calculate_actor_statistics(actors)
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_actor_by_id(actor_id):
    """Get a specific actor by ID"""
    try:
        if os.path.exists(app.config['ACTORS_FILE']):
            with open(app.config['ACTORS_FILE'], 'r') as f:
                actors = json.load(f)
            
            for actor in actors:
                if actor.get('id') == actor_id:
                    return actor
    except Exception as e:
        print(f"Error getting actor {actor_id}: {e}")
    
    return None

@app.route('/api/actors/<actor_id>')
def api_actor_details(actor_id):
    """API endpoint to get details for a specific actor"""
    try:
        actor = get_actor_by_id(actor_id)
        if actor:
            return jsonify(actor)
        else:
            return jsonify({'error': 'Actor not found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export')
def api_export():
    """API endpoint to export all data"""
    try:
        # Load all data
        with open(app.config['THREATS_FILE'], 'r') as f:
            threats = json.load(f)
        
        actors = []
        if os.path.exists(app.config['ACTORS_FILE']):
            with open(app.config['ACTORS_FILE'], 'r') as f:
                actors = json.load(f)
        
        tools = []
        if os.path.exists(app.config['TOOLS_FILE']):
            with open(app.config['TOOLS_FILE'], 'r') as f:
                tools = json.load(f)
        
        export_data = {
            'export_time': datetime.now().isoformat(),
            'threats': threats,
            'actors': actors,
            'tools': tools,
            'metadata': {
                'total_threats': len(threats),
                'total_actors': len(actors),
                'total_tools': len(tools)
            }
        }
        
        return jsonify(export_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Create data directory if it doesn't exist
    os.makedirs(app.config['DATA_DIR'], exist_ok=True)
    
    # Initialize empty data files if they don't exist
    for file_path in [app.config['THREATS_FILE'], app.config['ACTORS_FILE'], app.config['TOOLS_FILE']]:
        if not os.path.exists(file_path):
            with open(file_path, 'w') as f:
                json.dump([], f)
    
    # Set up background scheduler for automatic updates
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=update_threat_data,
        trigger="interval",
        hours=app.config['RSS_REFRESH_INTERVAL'],
        id='update_threats'
    )
    scheduler.start()
    
    # Shut down the scheduler when exiting the app
    atexit.register(lambda: scheduler.shutdown())
    
    # Initial data load
    update_threat_data()
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'])