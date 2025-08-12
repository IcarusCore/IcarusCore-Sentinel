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
from src.services.shodan_service import ShodanService
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
shodan_service = ShodanService()
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
        
        # Update Shodan data (if API key is available)
        if app.config['SHODAN_API_KEY']:
            shodan_data = shodan_service.fetch_vulnerabilities()
            if shodan_data:
                data_processor.process_shodan_data(shodan_data)
                print("✓ Shodan data updated")
        
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

@app.route('/shodan')
def shodan():
    """Shodan network intelligence page"""
    try:
        # Check if Shodan API key is configured
        if not app.config.get('SHODAN_API_KEY'):
            return render_template('shodan.html', 
                                 error="Shodan API key not configured",
                                 vulnerabilities=[],
                                 stats=None,
                                 api_info=None)
        
        # Get API information
        api_info = shodan_service.get_api_info()
        
        # Try different search strategies based on available credits
        vulnerabilities = []
        
        if api_info and api_info.get('query_credits', 0) > 0:
            # If we have credits, try to fetch real data
            vulnerabilities = shodan_service.fetch_vulnerabilities(limit=25)
            
            # If no vulnerabilities found, try a broader search
            if not vulnerabilities:
                vulnerabilities = shodan_service.fetch_internet_scan_data('port:80', limit=20)
        
        # If still no data or no credits, provide sample data for demonstration
        if not vulnerabilities:
            vulnerabilities = [
                {
                    'id': 'demo-shodan-1',
                    'name': 'Demo: Exposed HTTP Service',
                    'description': 'Sample data - Configure Shodan API key and credits to see real vulnerability data',
                    'ip_address': '203.0.113.1',
                    'port': 80,
                    'service': 'Apache',
                    'version': '2.4.41',
                    'severity': 'Medium',
                    'country': 'United States',
                    'city': 'San Francisco',
                    'organization': 'Example ISP',
                    'vulnerabilities': ['CVE-2023-Demo'],
                    'tags': ['demo', 'http', 'web-server'],
                    'date': datetime.now().isoformat()
                },
                {
                    'id': 'demo-shodan-2', 
                    'name': 'Demo: Exposed SSH Service',
                    'description': 'Sample data - Get Shodan credits to access real network intelligence',
                    'ip_address': '203.0.113.2',
                    'port': 22,
                    'service': 'OpenSSH',
                    'version': '7.4',
                    'severity': 'Low',
                    'country': 'Germany',
                    'city': 'Berlin',
                    'organization': 'Demo Hosting',
                    'vulnerabilities': [],
                    'tags': ['demo', 'ssh', 'remote-access'],
                    'date': datetime.now().isoformat()
                }
            ]
        
        # Calculate statistics
        stats = None
        if vulnerabilities:
            countries = {}
            services = {}
            
            for vuln in vulnerabilities:
                country = vuln.get('country', 'Unknown')
                service = vuln.get('service', 'Unknown')
                
                countries[country] = countries.get(country, 0) + 1
                services[service] = services.get(service, 0) + 1
            
            stats = {
                'total_vulnerabilities': len(vulnerabilities),
                'unique_countries': len(countries),
                'unique_services': len(services),
                'top_countries': sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10],
                'top_services': sorted(services.items(), key=lambda x: x[1], reverse=True)[:10]
            }
        
        return render_template('shodan.html',
                             vulnerabilities=vulnerabilities,
                             stats=stats,
                             api_info=api_info,
                             error=None)
        
    except Exception as e:
        print(f"Error loading Shodan data: {e}")
        return render_template('shodan.html',
                             error=f"Error loading Shodan data: {str(e)}",
                             vulnerabilities=[],
                             stats=None,
                             api_info=None)

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

@app.route('/api/shodan/host/<ip_address>')
def api_shodan_host(ip_address):
    """API endpoint to get detailed host information from Shodan"""
    try:
        if not app.config.get('SHODAN_API_KEY'):
            return jsonify({'error': 'Shodan API key not configured'}), 400
        
        host_info = shodan_service.fetch_host_info(ip_address)
        
        if host_info:
            return jsonify(host_info)
        else:
            return jsonify({'error': 'Host information not found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/shodan/search')
def api_shodan_search():
    """API endpoint for custom Shodan searches"""
    try:
        if not app.config.get('SHODAN_API_KEY'):
            return jsonify({'error': 'Shodan API key not configured'}), 400
        
        query = request.args.get('query', '')
        limit = request.args.get('limit', 50, type=int)
        
        if not query:
            return jsonify({'error': 'Query parameter is required'}), 400
        
        # Use the internet scan method for custom queries
        results = shodan_service.fetch_internet_scan_data(query=query, limit=limit)
        
        if results:
            return jsonify({
                'total': len(results),
                'results': results
            })
        else:
            return jsonify({'error': 'No results found'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/shodan/exploits')
def api_shodan_exploits():
    """API endpoint to search for exploits"""
    try:
        if not app.config.get('SHODAN_API_KEY'):
            return jsonify({'error': 'Shodan API key not configured'}), 400
        
        query = request.args.get('query', 'type:exploit')
        limit = request.args.get('limit', 20, type=int)
        
        exploits = shodan_service.search_exploits(query, limit)
        
        if exploits:
            return jsonify({
                'total': len(exploits),
                'exploits': exploits
            })
        else:
            return jsonify({'error': 'No exploits found'}), 404
            
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