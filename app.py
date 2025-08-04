from flask import Flask, render_template, jsonify, request
from datetime import datetime, timedelta
import json
import os
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

# Import our custom modules
from src.services.mitre_service import MitreService
from src.services.otx_service import OTXService
from src.services.cisa_service import CISAService
from src.services.rss_service import RSSService
from src.utils.data_processor import DataProcessor
from src.utils.helpers import format_date, truncate_text
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Initialize services
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
    """Update threat intelligence data from all sources"""
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

@app.route('/actors')
def actors():
    """Threat actors page"""
    try:
        actors = []
        if os.path.exists(app.config['ACTORS_FILE']):
            with open(app.config['ACTORS_FILE'], 'r') as f:
                actors = json.load(f)
        
        return render_template('actors.html', actors=actors)
    except Exception as e:
        print(f"Error loading actors: {e}")
        return render_template('actors.html', actors=[])

@app.route('/tools')
def tools():
    """Tools and techniques page"""
    try:
        tools = []
        if os.path.exists(app.config['TOOLS_FILE']):
            with open(app.config['TOOLS_FILE'], 'r') as f:
                tools = json.load(f)
        
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