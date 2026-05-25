# CGE
<img width="1280" height="853" alt="image" src="https://github.com/user-attachments/assets/db4aaaa9-d992-42a0-abc2-0247afd64cb5" />
## Overview
CGE is a passive reconnaissance and graph mapping tool that discovers subdomains, endpoints, and relationships between hosts through web crawling and analysis. It visualizes the results as an interactive graph and supports storing scans in Neo4j.
## Features
- Passive Subdomain Discovery: Extracts subdomains from SSL certificates, DNS TXT records, and web content
- Web Crawling: Recursively crawls discovered hosts to find endpoints and connections
- JavaScript Analysis: Parses JS files for fetch/XHR calls and SPA routes
- Form Processing: Automatically submits forms with test data
- Real-time Updates: Live graph updates during scanning via Server-Sent Events
- Neo4j Integration: Save and load scans from Neo4j database
- Interactive Visualization: Clickable graph nodes showing endpoints and request details
## Installation
```bash
git clone https://github.com/a11mut3d/CGE
pip install -r requirements.txt

optional
docker run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j:latest
```
## Usage
### Web Interface (Recommended)
```bash
python app.py
```
Then open http://localhost:5000 in your browser.
### Command Line Interface
```bash
# Basic scan
python cli.py example.com

# Save to JSON file
python cli.py example.com --format json --output results.json

# Save to Neo4j
python cli.py example.com --save-db

# Load previous scan from Neo4j
python cli.py example.com --load-scan scan_id_here

# Show detailed request information
python cli.py example.com --verbose

# With cookies
python cli.py example.com --cookies "session=abc123; user=test"
```
## Output Format
```json
{
  "nodes": [
    {"id": "example.com", "label": "example.com"},
    {"id": "api.example.com", "label": "api.example.com"}
  ],
  "edges": [
    {
      "source": "example.com",
      "target": "api.example.com",
      "method": "GET",
      "details": "/data"
    }
  ],
  "endpoints": {
    "example.com": ["GET /", "GET /login", "POST /api/submit"]
  },
  "requests": [...],
  "total_hosts": 5,
  "total_requests": 42
}
```

---
**[Mute Ecosystem](https://a11mut3d.github.io/MuteEcosystem/)** 
