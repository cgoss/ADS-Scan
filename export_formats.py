"""
Export Format Handlers
Supports CSV, JSON, HTML, and STIX 2.1 export formats
"""

import json
import csv
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path


def export_to_csv(results: List[Dict], output_path: str, fieldnames: List[str]):
    """
    Export results to CSV format

    Args:
        results: List of result dictionaries
        output_path: Output file path
        fieldnames: List of field names for CSV columns
    """
    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)


def export_to_json(results: List[Dict], output_path: str, scan_metadata: Dict[str, Any]):
    """
    Export results to JSON format with metadata

    Args:
        results: List of result dictionaries
        output_path: Output file path
        scan_metadata: Metadata about the scan
    """
    # Calculate statistics
    total_streams = len(results)
    high_risk = len([r for r in results if r.get('Combined_Risk') == 'HIGH'])
    medium_risk = len([r for r in results if r.get('Combined_Risk') == 'MEDIUM'])
    low_risk = len([r for r in results if r.get('Combined_Risk') == 'LOW'])
    unknown_risk = len([r for r in results if r.get('Combined_Risk') == 'UNKNOWN'])

    malicious_vt = len([r for r in results if isinstance(r.get('VT_Malicious'), int) and r['VT_Malicious'] > 0])
    malicious_ha = len([r for r in results if isinstance(r.get('HA_ThreatScore'), int) and r['HA_ThreatScore'] >= 70])

    output = {
        "scan_metadata": {
            "scan_date": scan_metadata.get('scan_date', datetime.now().isoformat()),
            "scan_path": scan_metadata.get('scan_path', ''),
            "scanner_version": "2.0.0",
            "total_streams": total_streams,
            "statistics": {
                "high_risk": high_risk,
                "medium_risk": medium_risk,
                "low_risk": low_risk,
                "unknown_risk": unknown_risk,
                "malicious_vt": malicious_vt,
                "malicious_ha": malicious_ha
            },
            "api_usage": scan_metadata.get('api_usage', {}),
            "cache_stats": scan_metadata.get('cache_stats', {})
        },
        "results": results
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, default=str)

    print(f"[+] JSON report saved to: {output_path}")


def export_to_html(results: List[Dict], output_path: str, scan_metadata: Dict[str, Any]):
    """
    Export results to interactive HTML format

    Args:
        results: List of result dictionaries
        output_path: Output file path
        scan_metadata: Metadata about the scan
    """
    # Calculate statistics
    total_streams = len(results)
    high_risk = len([r for r in results if r.get('Combined_Risk') == 'HIGH'])
    medium_risk = len([r for r in results if r.get('Combined_Risk') == 'MEDIUM'])
    low_risk = len([r for r in results if r.get('Combined_Risk') == 'LOW'])
    unknown_risk = len([r for r in results if r.get('Combined_Risk') == 'UNKNOWN'])

    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ADS Scanner Report - {scan_metadata.get('scan_date', datetime.now().strftime('%Y-%m-%d'))}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 30px;
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 32px;
        }}
        .subtitle {{
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid #ccc;
        }}
        .stat-card.high {{ border-left-color: #dc3545; }}
        .stat-card.medium {{ border-left-color: #ffc107; }}
        .stat-card.low {{ border-left-color: #28a745; }}
        .stat-card.unknown {{ border-left-color: #6c757d; }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .filters {{
            margin-bottom: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
        }}
        .filters input, .filters select {{
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-right: 10px;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th {{
            background: #343a40;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            position: sticky;
            top: 0;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #dee2e6;
            font-size: 13px;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .risk-high {{ color: #dc3545; font-weight: bold; }}
        .risk-medium {{ color: #ffc107; font-weight: bold; }}
        .risk-low {{ color: #28a745; font-weight: bold; }}
        .risk-unknown {{ color: #6c757d; }}
        .truncate {{
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-danger {{ background: #dc3545; color: white; }}
        .badge-warning {{ background: #ffc107; color: #333; }}
        .badge-success {{ background: #28a745; color: white; }}
        .badge-secondary {{ background: #6c757d; color: white; }}
        a {{ color: #007bff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 ADS Scanner Report</h1>
        <p class="subtitle">Scan Date: {scan_metadata.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))} |
           Path: {scan_metadata.get('scan_path', 'N/A')}</p>

        <div class="stats">
            <div class="stat-card high">
                <div class="stat-value">{high_risk}</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{medium_risk}</div>
                <div class="stat-label">Medium Risk</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">{low_risk}</div>
                <div class="stat-label">Low Risk</div>
            </div>
            <div class="stat-card unknown">
                <div class="stat-value">{unknown_risk}</div>
                <div class="stat-label">Unknown</div>
            </div>
        </div>

        <div class="filters">
            <input type="text" id="searchBox" placeholder="Search files..." onkeyup="filterTable()">
            <select id="riskFilter" onchange="filterTable()">
                <option value="">All Risk Levels</option>
                <option value="HIGH">High Risk</option>
                <option value="MEDIUM">Medium Risk</option>
                <option value="LOW">Low Risk</option>
                <option value="UNKNOWN">Unknown</option>
            </select>
        </div>

        <table id="resultsTable">
            <thead>
                <tr>
                    <th>Risk</th>
                    <th>File Name</th>
                    <th>Stream Name</th>
                    <th>Size</th>
                    <th>VT Detection</th>
                    <th>HA Score</th>
                    <th>Stream Type</th>
                    <th>Links</th>
                </tr>
            </thead>
            <tbody>
"""

    # Add table rows
    for result in results:
        risk = result.get('Combined_Risk', 'UNKNOWN')
        risk_class = f"risk-{risk.lower()}"

        vt_detection = result.get('VT_DetectionRatio', 'N/A')
        ha_score = result.get('HA_ThreatScore', 'N/A')

        vt_link = result.get('VT_Link', '')
        ha_link = result.get('HA_ReportURL', '')

        links = []
        if vt_link and vt_link != 'N/A':
            links.append(f'<a href="{vt_link}" target="_blank">VT</a>')
        if ha_link and ha_link != 'N/A':
            links.append(f'<a href="{ha_link}" target="_blank">HA</a>')
        links_html = ' | '.join(links) if links else 'N/A'

        html += f"""
                <tr>
                    <td><span class="badge badge-{risk.lower() if risk != 'UNKNOWN' else 'secondary'}">{risk}</span></td>
                    <td class="truncate" title="{result.get('FilePath', '')}">{result.get('FileName', '')}</td>
                    <td>{result.get('StreamName', '')}</td>
                    <td>{result.get('StreamSize', 0)} bytes</td>
                    <td class="{risk_class}">{vt_detection}</td>
                    <td class="{risk_class}">{ha_score}</td>
                    <td>{result.get('StreamType', 'Unknown')}</td>
                    <td>{links_html}</td>
                </tr>
"""

    html += """
            </tbody>
        </table>
    </div>

    <script>
        function filterTable() {
            const searchBox = document.getElementById('searchBox');
            const riskFilter = document.getElementById('riskFilter');
            const table = document.getElementById('resultsTable');
            const rows = table.getElementsByTagName('tr');

            const searchTerm = searchBox.value.toLowerCase();
            const riskValue = riskFilter.value;

            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const fileName = row.cells[1].textContent.toLowerCase();
                const streamName = row.cells[2].textContent.toLowerCase();
                const risk = row.cells[0].textContent.trim();

                const matchesSearch = fileName.includes(searchTerm) || streamName.includes(searchTerm);
                const matchesRisk = !riskValue || risk === riskValue;

                row.style.display = (matchesSearch && matchesRisk) ? '' : 'none';
            }
        }
    </script>
</body>
</html>
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"[+] HTML report saved to: {output_path}")


def export_to_stix(results: List[Dict], output_path: str, scan_metadata: Dict[str, Any]):
    """
    Export malicious results to STIX 2.1 format

    Args:
        results: List of result dictionaries
        output_path: Output file path
        scan_metadata: Metadata about the scan
    """
    # Filter for malicious results only
    malicious_results = [
        r for r in results
        if r.get('Combined_Risk') in ['HIGH', 'MEDIUM'] or
        (isinstance(r.get('VT_Malicious'), int) and r['VT_Malicious'] > 0)
    ]

    # Build STIX bundle
    stix_objects = []

    # Identity object
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--" + "ads-scanner-" + datetime.now().strftime('%Y%m%d'),
        "created": datetime.now().isoformat() + "Z",
        "modified": datetime.now().isoformat() + "Z",
        "name": "ADS Scanner",
        "identity_class": "system"
    }
    stix_objects.append(identity)

    # Create indicators for each malicious hash
    for idx, result in enumerate(malicious_results):
        file_hash = result.get('StreamSHA256', '')
        if not file_hash:
            continue

        indicator_id = f"indicator--ads-{idx}-{file_hash[:8]}"

        # Build description
        description = f"Malicious alternate data stream detected: {result.get('FileName', 'unknown')}:{result.get('StreamName', 'unknown')}"

        if result.get('VT_Malicious') and result['VT_Malicious'] > 0:
            description += f" | VirusTotal: {result.get('VT_DetectionRatio', 'N/A')} detections"

        if result.get('HA_ThreatScore'):
            description += f" | Hybrid Analysis: {result.get('HA_Verdict', 'unknown')} (score: {result['HA_ThreatScore']})"

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": datetime.now().isoformat() + "Z",
            "modified": datetime.now().isoformat() + "Z",
            "name": f"Malicious file hash: {file_hash[:16]}...",
            "description": description,
            "pattern": f"[file:hashes.SHA256 = '{file_hash}']",
            "pattern_type": "stix",
            "valid_from": datetime.now().isoformat() + "Z",
            "labels": ["malicious-activity", "alternate-data-stream"]
        }
        stix_objects.append(indicator)

        # Create observed-data object
        observed_data = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": f"observed-data--ads-{idx}-{file_hash[:8]}",
            "created": datetime.now().isoformat() + "Z",
            "modified": datetime.now().isoformat() + "Z",
            "first_observed": result.get('ScanDate', datetime.now().isoformat()) + "Z" if isinstance(result.get('ScanDate'), str) else datetime.now().isoformat() + "Z",
            "last_observed": result.get('ScanDate', datetime.now().isoformat()) + "Z" if isinstance(result.get('ScanDate'), str) else datetime.now().isoformat() + "Z",
            "number_observed": 1,
            "objects": {
                "0": {
                    "type": "file",
                    "hashes": {
                        "SHA-256": file_hash
                    },
                    "name": f"{result.get('FileName', 'unknown')}:{result.get('StreamName', 'unknown')}",
                    "size": result.get('StreamSize', 0)
                }
            }
        }
        stix_objects.append(observed_data)

    # Build STIX bundle
    stix_bundle = {
        "type": "bundle",
        "id": "bundle--ads-scanner-" + datetime.now().strftime('%Y%m%d%H%M%S'),
        "objects": stix_objects
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(stix_bundle, f, indent=2)

    print(f"[+] STIX 2.1 report saved to: {output_path} ({len(malicious_results)} indicators)")


def calculate_combined_risk(vt_result: Dict, ha_result: Dict, otx_result: Dict = None, metadefender_result: Dict = None) -> str:
    """
    Calculate combined risk assessment from multiple threat intelligence sources

    Args:
        vt_result: VirusTotal result dictionary
        ha_result: Hybrid Analysis result dictionary
        otx_result: AlienVault OTX result dictionary (optional)
        metadefender_result: MetaDefender result dictionary (optional)

    Returns:
        Risk level: HIGH, MEDIUM, LOW, or UNKNOWN
    """
    # Check if results are available
    vt_found = vt_result and vt_result.get('found', False)
    ha_found = ha_result and ha_result.get('found', False)
    otx_found = otx_result and otx_result.get('found', False) if otx_result else False
    md_found = metadefender_result and metadefender_result.get('found', False) if metadefender_result else False

    if not (vt_found or ha_found or otx_found or md_found):
        return 'UNKNOWN'

    # Extract values
    vt_malicious = vt_result.get('malicious', 0) if vt_found else 0
    vt_suspicious = vt_result.get('suspicious', 0) if vt_found else 0
    ha_score = ha_result.get('threat_score', 0) if ha_found else 0
    otx_reputation = otx_result.get('reputation', 0) if otx_found else 0
    md_detected = metadefender_result.get('detected', 0) if md_found else 0

    # HIGH: VT malicious >= 3 OR HA threat_score >= 70 OR MetaDefender detected >= 5 OR OTX reputation >= 50
    if (vt_malicious >= 3 or 
        ha_score >= 70 or 
        md_detected >= 5 or 
        otx_reputation >= 50):
        return 'HIGH'

    # MEDIUM: VT malicious > 0 OR HA threat_score >= 40 OR VT suspicious >= 5 OR MetaDefender detected > 0 OR OTX reputation >= 20
    if (vt_malicious > 0 or 
        ha_score >= 40 or 
        vt_suspicious >= 5 or 
        md_detected > 0 or 
        otx_reputation >= 20):
        return 'MEDIUM'

    # LOW: VT malicious == 0 AND HA threat_score < 20 AND MetaDefender detected = 0 AND OTX reputation < 10
    if (vt_malicious == 0 and 
        ha_score < 20 and 
        md_detected == 0 and 
        otx_reputation < 10):
        return 'LOW'

    # Default to UNKNOWN
    return 'UNKNOWN'
