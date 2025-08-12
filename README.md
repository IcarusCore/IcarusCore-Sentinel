# Threat Intelligence Dashboard

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen)
![Unraid](https://img.shields.io/badge/unraid-compatible-orange)
![License](https://img.shields.io/badge/license-MIT-green)

A comprehensive cybersecurity threat intelligence dashboard that aggregates and displays real-time threat data from multiple sources including MITRE ATT&CK, CISA, AlienVault OTX, and security RSS feeds.

## 🚀 Quick Start for Unraid

### Method 1: Using Community Applications (Recommended)

1. **Install Community Applications plugin** (if not already installed)
2. **Search for "Threat Intelligence Dashboard"** in CA
3. **Click Install**
4. **Configure Variables:**
   - Set your OTX API Key (optional but recommended)
   - Adjust timezone if needed
   - Configure data paths
5. **Click Apply**

### Method 2: Manual Docker Setup in Unraid

1. **Go to Docker tab** in Unraid WebUI
2. **Click "Add Container"**
3. **Configure as follows:**

```
Name: ThreatIntelDashboard
Repository: ghcr.io/yourusername/threat-intel-dashboard:latest
```

4. **Add these configurations:**

| Setting | Value |
|---------|-------|
| **Network Type** | Bridge |
| **Console Shell** | Shell |
| **WebUI** | http://[IP]:[PORT:5000]/ |

5. **Add Port Mapping:**
   - Container Port: `5000`
   - Host Port: `5000`

6. **Add Volume Mappings:**
   - Container Path: `/app/data` → Host Path: `/mnt/user/appdata/threatintel/data`
   - Container Path: `/app/logs` → Host Path: `/mnt/user/appdata/threatintel/logs`

7. **Add Environment Variables:**

Click "Add another Path, Port, Variable, Label or Device"

**Essential Variable (Recommended):**
- **Name:** `OTX_API_KEY`
- **Key:** `OTX_API_KEY`
- **Value:** `your-api-key-here`
- **Description:** AlienVault OTX API Key

**Optional Variables:**
- `TZ` - Timezone (e.g., `America/New_York`)
- `SECRET_KEY` - Flask secret key (auto-generated if not set)
- `MITRE_REFRESH_INTERVAL` - Hours between MITRE updates (default: 24)
- `OTX_REFRESH_INTERVAL` - Hours between OTX updates (default: 6)
- `CISA_REFRESH_INTERVAL` - Hours between CISA updates (default: 4)
- `RSS_REFRESH_INTERVAL` - Hours between RSS updates (default: 2)

## 📦 Building from GitHub

### Prerequisites
- Docker installed
- Git installed
- GitHub account

### Steps to Deploy Your Own Version

1. **Fork this repository** on GitHub

2. **Clone your fork:**
```bash
git clone https://github.com/yourusername/threat-intel-dashboard.git
cd threat-intel-dashboard
```

3. **Build the Docker image:**
```bash
docker build -t threat-intel-dashboard .
```

4. **Run locally for testing:**
```bash
docker run -d \
  --name threatintel \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  -e OTX_API_KEY="your-api-key" \
  -e TZ="America/New_York" \
  threat-intel-dashboard
```

### Publishing to GitHub Container Registry

1. **Create a Personal Access Token:**
   - Go to GitHub Settings → Developer settings → Personal access tokens
   - Create a token with `write:packages` permission

2. **Login to GitHub Container Registry:**
```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
```

3. **Tag your image:**
```bash
docker tag threat-intel-dashboard ghcr.io/yourusername/threat-intel-dashboard:latest
docker tag threat-intel-dashboard ghcr.io/yourusername/threat-intel-dashboard:v1.0.0
```

4. **Push to registry:**
```bash
docker push ghcr.io/yourusername/threat-intel-dashboard:latest
docker push ghcr.io/yourusername/threat-intel-dashboard:v1.0.0
```

5. **Make package public** (optional):
   - Go to your GitHub profile → Packages
   - Click on the package
   - Settings → Change visibility → Public

## 🔑 Getting API Keys

### AlienVault OTX API Key (Free)

1. Go to [https://otx.alienvault.com](https://otx.alienvault.com)
2. Create a free account
3. Navigate to Settings → API Integration
4. Copy your API key
5. Add it to your Unraid container variables

## 📊 Features

- **Real-time Threat Monitoring** - Live updates from multiple sources
- **MITRE ATT&CK Integration** - Complete framework coverage
- **APT Group Tracking** - Monitor threat actor activities
- **Security Tools Database** - Comprehensive tool analysis
- **CISA Alerts** - Government security advisories
- **RSS Feed Aggregation** - Security news from top sources
- **Search & Filtering** - Advanced search capabilities
- **Export Functionality** - Export data in JSON format

## 🗂️ Data Persistence

The dashboard stores data in `/app/data` which should be mapped to your Unraid appdata folder. This ensures:
- Threat intelligence persists between container restarts
- Historical data is maintained
- Updates are incremental, not full refreshes

## 🔒 Security Considerations

1. **Change the SECRET_KEY** in production
2. **Use a reverse proxy** (like SWAG) with authentication for internet exposure
3. **Keep the container updated** regularly
4. **Monitor the logs** in `/app/logs` for any issues

## 🐛 Troubleshooting

### Container won't start
- Check logs: `docker logs ThreatIntelDashboard`
- Verify port 5000 isn't already in use
- Ensure data directory has proper permissions

### No data showing
- Verify internet connectivity from container
- Check if API keys are set correctly
- Wait for initial data fetch (can take 2-5 minutes)
- Check logs for any API errors

### Permission issues
- Ensure data directories are owned by nobody:users (99:100)
- Run: `chown -R 99:100 /mnt/user/appdata/threatintel`

## 📝 Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `OTX_API_KEY` | (empty) | AlienVault OTX API key for threat intelligence |
| `SECRET_KEY` | (auto) | Flask secret key for session encryption |
| `TZ` | UTC | Container timezone |
| `FLASK_ENV` | production | Flask environment (production/development) |
| `FLASK_DEBUG` | False | Enable debug mode (not for production) |
| `MITRE_REFRESH_INTERVAL` | 24 | Hours between MITRE ATT&CK updates |
| `OTX_REFRESH_INTERVAL` | 6 | Hours between OTX updates |
| `CISA_REFRESH_INTERVAL` | 4 | Hours between CISA alert updates |
| `RSS_REFRESH_INTERVAL` | 2 | Hours between RSS feed updates |
| `ITEMS_PER_PAGE` | 20 | Items per page in listings |

## 🔄 Updates

To update the container:

1. **Stop the container** in Unraid Docker tab
2. **Click "Check for Updates"** or force update
3. **Start the container**

Your data in `/app/data` will be preserved.

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 💬 Support

- **GitHub Issues:** [Report bugs or request features](https://github.com/yourusername/threat-intel-dashboard/issues)
- **Unraid Forums:** Post in the Docker Containers support thread
- **Documentation:** Check the [Wiki](https://github.com/yourusername/threat-intel-dashboard/wiki)

## 🙏 Credits

- MITRE ATT&CK Framework
- CISA Cybersecurity Advisories  
- AlienVault OTX Community
- Security community RSS feed providers

---

**Made with ❤️ for the Unraid Community**