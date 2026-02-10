#!/usr/bin/env python3
"""
PhantomSurface - Web Dashboard
Flask-based web interface for PhantomSurface.

Author: Security Engineering Student
License: MIT
"""

from flask import Flask, render_template_string, request, jsonify, send_file
import os
import sys
import json
import threading
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import PhantomSurface

app = Flask(__name__)
app.config['SECRET_KEY'] = 'phantomsurface-secret-key-change-in-production'

# Store scan status
scan_status = {
    'running': False,
    'progress': 0,
    'message': '',
    'results': None
}

# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhantomSurface - Attack Surface Mapper</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
        }

        .header h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header p {
            color: #666;
            font-size: 1.1em;
        }

        .card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
        }

        input[type="text"],
        select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e8ed;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }

        input[type="text"]:focus,
        select:focus {
            outline: none;
            border-color: #667eea;
        }

        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }

        .btn:hover {
            transform: translateY(-2px);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .alert {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }

        .alert-warning {
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
        }

        .alert-info {
            background-color: #d1ecf1;
            border: 1px solid #17a2b8;
            color: #0c5460;
        }

        .alert-success {
            background-color: #d4edda;
            border: 1px solid #28a745;
            color: #155724;
        }

        .status-box {
            padding: 20px;
            background: #f8f9fa;
            border-radius: 5px;
            margin-top: 20px;
            display: none;
        }

        .status-box.active {
            display: block;
        }

        .progress-bar {
            width: 100%;
            height: 30px;
            background: #e1e8ed;
            border-radius: 15px;
            overflow: hidden;
            margin: 15px 0;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            width: 0%;
            transition: width 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
        }

        .results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }

        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 1em;
            opacity: 0.9;
        }

        .threat-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9em;
            margin: 5px;
        }

        .critical { background: #dc3545; color: white; }
        .high { background: #fd7e14; color: white; }
        .medium { background: #ffc107; color: #333; }
        .low { background: #28a745; color: white; }

        .visualization {
            text-align: center;
            margin-top: 20px;
        }

        .visualization img {
            max-width: 100%;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .file-links {
            display: flex;
            gap: 15px;
            margin-top: 20px;
        }

        .file-link {
            flex: 1;
            padding: 15px;
            background: #f8f9fa;
            border: 2px solid #e1e8ed;
            border-radius: 5px;
            text-align: center;
            text-decoration: none;
            color: #333;
            font-weight: 600;
            transition: all 0.3s;
        }

        .file-link:hover {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }

        .footer {
            text-align: center;
            color: white;
            margin-top: 30px;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 PhantomSurface</h1>
            <p>Intelligent Attack Surface Mapping System</p>
        </div>

        <div class="card">
            <div class="alert alert-warning">
                ⚠️ <strong>Ethical Usage Warning:</strong> Only scan domains you own or have explicit written authorization to test. Unauthorized scanning is illegal and unethical.
            </div>

            <form id="scanForm">
                <div class="form-group">
                    <label for="target">Target Domain</label>
                    <input type="text" id="target" name="target" placeholder="example.com" required>
                </div>

                <div class="form-group">
                    <label for="scanType">Scan Type</label>
                    <select id="scanType" name="scanType">
                        <option value="quick">Quick Scan (Fast, Common Ports)</option>
                        <option value="full" selected>Full Scan (Comprehensive)</option>
                    </select>
                </div>

                <button type="submit" class="btn" id="startBtn">Start Scan</button>
            </form>

            <div class="status-box" id="statusBox">
                <h3 id="statusMessage">Initializing scan...</h3>
                <div class="progress-bar">
                    <div class="progress-fill" id="progressFill">0%</div>
                </div>
                <p id="statusDetail"></p>
            </div>
        </div>

        <div class="card" id="resultsCard" style="display: none;">
            <h2>Scan Results</h2>
            
            <div class="results-grid" id="statsGrid"></div>

            <div class="file-links">
                <a href="/download/json" class="file-link" id="jsonLink">📄 Download JSON Results</a>
                <a href="/download/image" class="file-link" id="imageLink">🖼️ Download Visualization</a>
            </div>

            <div class="visualization" id="visualization"></div>
        </div>

        <div class="footer">
            <p>PhantomSurface v1.0.0 | Developed for Defensive Security | Use Responsibly</p>
        </div>
    </div>

    <script>
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const target = document.getElementById('target').value;
            const scanType = document.getElementById('scanType').value;
            const startBtn = document.getElementById('startBtn');
            const statusBox = document.getElementById('statusBox');
            const resultsCard = document.getElementById('resultsCard');
            
            // Reset and show status
            startBtn.disabled = true;
            statusBox.classList.add('active');
            resultsCard.style.display = 'none';
            
            try {
                // Start scan
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, scanType})
                });
                
                const data = await response.json();
                
                if (data.success) {
                    // Poll for status
                    pollStatus();
                } else {
                    alert('Error starting scan: ' + data.message);
                    startBtn.disabled = false;
                    statusBox.classList.remove('active');
                }
            } catch (error) {
                alert('Error: ' + error.message);
                startBtn.disabled = false;
                statusBox.classList.remove('active');
            }
        });
        
        async function pollStatus() {
            const statusMessage = document.getElementById('statusMessage');
            const progressFill = document.getElementById('progressFill');
            const statusDetail = document.getElementById('statusDetail');
            const startBtn = document.getElementById('startBtn');
            const statusBox = document.getElementById('statusBox');
            const resultsCard = document.getElementById('resultsCard');
            
            const interval = setInterval(async () => {
                try {
                    const response = await fetch('/api/status');
                    const data = await response.json();
                    
                    statusMessage.textContent = data.message;
                    progressFill.style.width = data.progress + '%';
                    progressFill.textContent = data.progress + '%';
                    
                    if (!data.running && data.results) {
                        clearInterval(interval);
                        displayResults(data.results);
                        statusBox.classList.remove('active');
                        resultsCard.style.display = 'block';
                        startBtn.disabled = false;
                    } else if (!data.running && !data.results) {
                        clearInterval(interval);
                        alert('Scan failed or was interrupted');
                        statusBox.classList.remove('active');
                        startBtn.disabled = false;
                    }
                } catch (error) {
                    console.error('Status poll error:', error);
                }
            }, 2000);
        }
        
        function displayResults(results) {
            const statsGrid = document.getElementById('statsGrid');
            const visualization = document.getElementById('visualization');
            
            // Display statistics
            const stats = [
                {label: 'Total Assets', value: results.assets.total_assets},
                {label: 'Unique IPs', value: results.assets.unique_ips},
                {label: 'Open Ports', value: results.network_scan.total_open_ports},
                {label: 'Risk Score', value: results.threats.overall_risk_score + '/100'}
            ];
            
            statsGrid.innerHTML = stats.map(stat => `
                <div class="stat-card">
                    <div class="stat-number">${stat.value}</div>
                    <div class="stat-label">${stat.label}</div>
                </div>
            `).join('');
            
            // Display visualization
            visualization.innerHTML = `
                <h3>Attack Surface Map</h3>
                <img src="/visualization" alt="Attack Surface Visualization">
            `;
        }
    </script>
</body>
</html>
"""


def run_scan_background(target, scan_type):
    """Run scan in background thread."""
    global scan_status
    
    try:
        scan_status['running'] = True
        scan_status['progress'] = 10
        scan_status['message'] = 'Initializing scan...'
        
        # Create scanner
        scanner = PhantomSurface(
            target=target,
            scan_type=scan_type,
            output_dir='output'
        )
        
        scan_status['progress'] = 25
        scan_status['message'] = 'Discovering assets...'
        
        # Run scan
        results = scanner.run_scan()
        
        scan_status['progress'] = 100
        scan_status['message'] = 'Scan complete!'
        scan_status['results'] = results
        scan_status['running'] = False
        
    except Exception as e:
        scan_status['running'] = False
        scan_status['message'] = f'Scan failed: {str(e)}'
        scan_status['results'] = None


@app.route('/')
def index():
    """Render main dashboard page."""
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """API endpoint to start a new scan."""
    global scan_status
    
    if scan_status['running']:
        return jsonify({'success': False, 'message': 'Scan already running'})
    
    data = request.json
    target = data.get('target')
    scan_type = data.get('scanType', 'full')
    
    if not target:
        return jsonify({'success': False, 'message': 'Target domain required'})
    
    # Reset status
    scan_status = {
        'running': True,
        'progress': 0,
        'message': 'Starting scan...',
        'results': None
    }
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan_background, args=(target, scan_type))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Scan started'})


@app.route('/api/status')
def get_status():
    """API endpoint to get scan status."""
    return jsonify(scan_status)


@app.route('/visualization')
def get_visualization():
    """Serve visualization image."""
    try:
        return send_file('output/attack_surface.png', mimetype='image/png')
    except:
        return "Visualization not available", 404


@app.route('/download/json')
def download_json():
    """Download JSON results."""
    try:
        return send_file('output/scan_results.json', 
                        mimetype='application/json',
                        as_attachment=True,
                        download_name='scan_results.json')
    except:
        return "Results not available", 404


@app.route('/download/image')
def download_image():
    """Download visualization image."""
    try:
        return send_file('output/attack_surface.png',
                        mimetype='image/png',
                        as_attachment=True,
                        download_name='attack_surface.png')
    except:
        return "Visualization not available", 404


def main():
    """Start Flask web server."""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        PhantomSurface Web Dashboard Starting...               ║
║                                                               ║
║  Access the dashboard at: http://localhost:5000               ║
║                                                               ║
║  Press Ctrl+C to stop the server                              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=5000, debug=False)


if __name__ == '__main__':
    main()
