<#
.SYNOPSIS
    Export Format Handlers for ADS Scanner (PowerShell Module)

.DESCRIPTION
    Provides functions for exporting scan results in multiple formats:
    CSV, JSON, HTML, and STIX 2.1
#>

function Export-ADSToJSON {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Results,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [Parameter(Mandatory=$true)]
        [hashtable]$ScanMetadata
    )

    # Calculate statistics
    $totalStreams = $Results.Count
    $highRisk = ($Results | Where-Object { $_.Combined_Risk -eq 'HIGH' }).Count
    $mediumRisk = ($Results | Where-Object { $_.Combined_Risk -eq 'MEDIUM' }).Count
    $lowRisk = ($Results | Where-Object { $_.Combined_Risk -eq 'LOW' }).Count
    $unknownRisk = ($Results | Where-Object { $_.Combined_Risk -eq 'UNKNOWN' }).Count

    $maliciousVT = ($Results | Where-Object { $_.VT_Malicious -is [int] -and $_.VT_Malicious -gt 0 }).Count
    $maliciousHA = ($Results | Where-Object { $_.HA_ThreatScore -is [int] -and $_.HA_ThreatScore -ge 70 }).Count

    $output = @{
        scan_metadata = @{
            scan_date = $ScanMetadata.scan_date
            scan_path = $ScanMetadata.scan_path
            scanner_version = "2.0.0"
            total_streams = $totalStreams
            statistics = @{
                high_risk = $highRisk
                medium_risk = $mediumRisk
                low_risk = $lowRisk
                unknown_risk = $unknownRisk
                malicious_vt = $maliciousVT
                malicious_ha = $maliciousHA
            }
            api_usage = $ScanMetadata.api_usage
            cache_stats = $ScanMetadata.cache_stats
        }
        results = $Results
    }

    $json = $output | ConvertTo-Json -Depth 10
    $json | Set-Content -Path $OutputPath -Encoding UTF8

    Write-Host "[+] JSON report saved to: $OutputPath" -ForegroundColor Green
}

function Export-ADSToHTML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Results,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [Parameter(Mandatory=$true)]
        [hashtable]$ScanMetadata
    )

    # Calculate statistics
    $totalStreams = $Results.Count
    $highRisk = ($Results | Where-Object { $_.Combined_Risk -eq 'HIGH' }).Count
    $mediumRisk = ($Results | Where-Object { $_.Combined_Risk -eq 'MEDIUM' }).Count
    $lowRisk = ($Results | Where-Object { $_.Combined_Risk -eq 'LOW' }).Count
    $unknownRisk = ($Results | Where-Object { $_.Combined_Risk -eq 'UNKNOWN' }).Count

    $scanDate = $ScanMetadata.scan_date
    $scanPath = $ScanMetadata.scan_path

    # Start HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ADS Scanner Report - $scanDate</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 30px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 32px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid #ccc;
        }
        .stat-card.high { border-left-color: #dc3545; }
        .stat-card.medium { border-left-color: #ffc107; }
        .stat-card.low { border-left-color: #28a745; }
        .stat-card.unknown { border-left-color: #6c757d; }
        .stat-value {
            font-size: 36px;
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }
        .stat-label {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .filters {
            margin-bottom: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
        }
        .filters input, .filters select {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-right: 10px;
            font-size: 14px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th {
            background: #343a40;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            position: sticky;
            top: 0;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #dee2e6;
            font-size: 13px;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-low { color: #28a745; font-weight: bold; }
        .risk-unknown { color: #6c757d; }
        .truncate {
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-danger { background: #dc3545; color: white; }
        .badge-warning { background: #ffc107; color: #333; }
        .badge-success { background: #28a745; color: white; }
        .badge-secondary { background: #6c757d; color: white; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 ADS Scanner Report</h1>
        <p class="subtitle">Scan Date: $scanDate | Path: $scanPath</p>

        <div class="stats">
            <div class="stat-card high">
                <div class="stat-value">$highRisk</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">$mediumRisk</div>
                <div class="stat-label">Medium Risk</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">$lowRisk</div>
                <div class="stat-label">Low Risk</div>
            </div>
            <div class="stat-card unknown">
                <div class="stat-value">$unknownRisk</div>
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
"@

    # Add table rows
    foreach ($result in $Results) {
        $risk = $result.Combined_Risk
        $riskClass = "risk-$($risk.ToLower())"
        $badgeClass = switch ($risk) {
            'HIGH' { 'badge-danger' }
            'MEDIUM' { 'badge-warning' }
            'LOW' { 'badge-success' }
            default { 'badge-secondary' }
        }

        $vtDetection = $result.VT_DetectionRatio
        $haScore = $result.HA_ThreatScore

        $links = @()
        if ($result.VT_Link -ne 'N/A') {
            $links += "<a href='$($result.VT_Link)' target='_blank'>VT</a>"
        }
        if ($result.HA_ReportURL -ne 'N/A') {
            $links += "<a href='$($result.HA_ReportURL)' target='_blank'>HA</a>"
        }
        $linksHtml = if ($links.Count -gt 0) { $links -join ' | ' } else { 'N/A' }

        $html += @"
                <tr>
                    <td><span class="badge $badgeClass">$risk</span></td>
                    <td class="truncate" title="$($result.FilePath)">$($result.FileName)</td>
                    <td>$($result.StreamName)</td>
                    <td>$($result.StreamSize) bytes</td>
                    <td class="$riskClass">$vtDetection</td>
                    <td class="$riskClass">$haScore</td>
                    <td>$($result.StreamType)</td>
                    <td>$linksHtml</td>
                </tr>
"@
    }

    # Close HTML
    $html += @"
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
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8

    Write-Host "[+] HTML report saved to: $OutputPath" -ForegroundColor Green
}

function Export-ADSToSTIX {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Results,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [Parameter(Mandatory=$true)]
        [hashtable]$ScanMetadata
    )

    # Filter for malicious results only
    $maliciousResults = $Results | Where-Object {
        $_.Combined_Risk -in @('HIGH', 'MEDIUM') -or
        ($_.VT_Malicious -is [int] -and $_.VT_Malicious -gt 0)
    }

    # Build STIX bundle
    $stixObjects = @()

    # Identity object
    $timestamp = Get-Date -Format 'o'
    $identity = @{
        type = "identity"
        spec_version = "2.1"
        id = "identity--ads-scanner-$(Get-Date -Format 'yyyyMMdd')"
        created = $timestamp
        modified = $timestamp
        name = "ADS Scanner"
        identity_class = "system"
    }
    $stixObjects += $identity

    # Create indicators for each malicious hash
    $idx = 0
    foreach ($result in $maliciousResults) {
        $fileHash = $result.StreamSHA256
        if ([string]::IsNullOrEmpty($fileHash)) { continue }

        $indicatorId = "indicator--ads-$idx-$($fileHash.Substring(0,8))"

        # Build description
        $description = "Malicious alternate data stream detected: $($result.FileName):$($result.StreamName)"

        if ($result.VT_Malicious -and $result.VT_Malicious -gt 0) {
            $description += " | VirusTotal: $($result.VT_DetectionRatio) detections"
        }

        if ($result.HA_ThreatScore) {
            $description += " | Hybrid Analysis: $($result.HA_Verdict) (score: $($result.HA_ThreatScore))"
        }

        $indicator = @{
            type = "indicator"
            spec_version = "2.1"
            id = $indicatorId
            created = $timestamp
            modified = $timestamp
            name = "Malicious file hash: $($fileHash.Substring(0,16))..."
            description = $description
            pattern = "[file:hashes.SHA256 = '$fileHash']"
            pattern_type = "stix"
            valid_from = $timestamp
            labels = @("malicious-activity", "alternate-data-stream")
        }
        $stixObjects += $indicator

        # Create observed-data object
        $observedData = @{
            type = "observed-data"
            spec_version = "2.1"
            id = "observed-data--ads-$idx-$($fileHash.Substring(0,8))"
            created = $timestamp
            modified = $timestamp
            first_observed = "$timestamp"
            last_observed = "$timestamp"
            number_observed = 1
            objects = @{
                "0" = @{
                    type = "file"
                    hashes = @{
                        "SHA-256" = $fileHash
                    }
                    name = "$($result.FileName):$($result.StreamName)"
                    size = $result.StreamSize
                }
            }
        }
        $stixObjects += $observedData

        $idx++
    }

    # Build STIX bundle
    $stixBundle = @{
        type = "bundle"
        id = "bundle--ads-scanner-$(Get-Date -Format 'yyyyMMddHHmmss')"
        objects = $stixObjects
    }

    $json = $stixBundle | ConvertTo-Json -Depth 10
    $json | Set-Content -Path $OutputPath -Encoding UTF8

    Write-Host "[+] STIX 2.1 report saved to: $OutputPath ($($maliciousResults.Count) indicators)" -ForegroundColor Green
}

# Export for dot-sourcing
Export-ModuleMember -Function *
