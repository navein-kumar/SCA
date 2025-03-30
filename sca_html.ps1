<#
.SYNOPSIS
    Processes Wazuh SCA Windows audit checks with HTML output
.DESCRIPTION
    Enhanced version with complete field output in HTML format
#>

# Load YAML module
try {
    Import-Module PowerShell-YAML -ErrorAction Stop
}
catch {
    Write-Host "ERROR: Install module first: Install-Module PowerShell-YAML -Force" -ForegroundColor Red
    exit 1
}

# HTML template with styling and table structure
$htmlTemplate = @"
<!DOCTYPE html>
<html>
<head>
    <title>SCA Audit Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2a5885; }
        .summary { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .summary-item { margin: 5px 0; }
        .passed { color: green; }
        .failed { color: red; }
        .errors { color: orange; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background-color: #2a5885; color: white; text-align: left; padding: 10px; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #e6f2ff; }
        .status-pass { background-color: #dff0d8; }
        .status-fail { background-color: #f2dede; }
        .status-error { background-color: #fcf8e3; }
        .details { display: none; }
        .toggle-details { color: #2a5885; cursor: pointer; }
    </style>
    <script>
        function toggleDetails(id) {
            var element = document.getElementById(id);
            if (element.style.display === "none") {
                element.style.display = "table-row";
            } else {
                element.style.display = "none";
            }
        }
    </script>
</head>
<body>
    <h1>SCA Audit Results</h1>
    <div class="summary">
        <div class="summary-item">Report generated on: {DATE}</div>
        <div class="summary-item">Total checks: {TOTAL}</div>
        <div class="summary-item passed">Passed: {PASSED}</div>
        <div class="summary-item failed">Failed: {FAILED}</div>
        <div class="summary-item errors">Errors: {ERRORS}</div>
    </div>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Status</th>
                <th>Expected</th>
                <th>Actual</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            {CONTENT}
        </tbody>
    </table>
</body>
</html>
"@

function Process-SCACheck {
    param ($check)

    $result = @{
        ID          = $check.id
        Title       = $check.title
        Description = $check.description
        Compliance  = if ($check.compliance) { ($check.compliance | Out-String).Trim() } else { "N/A" }
        Remediation = $check.remediation
        Status      = "FAIL"
        ActualValue = "N/A"
        Expected    = "N/A"
        Error       = $null
    }

    try {
        if ($check.rules -and $check.rules[0] -match "r:(.+?)\s*->\s*(.+?)\s*->\s*(.+)") {
            $path = "HKLM:" + $Matches[1].Replace("HKEY_LOCAL_MACHINE\", "")
            $name = $Matches[2]
            $expected = $Matches[3]
            $result.Expected = $expected

            try {
                $regValue = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
                $actual = $regValue.$name
                $result.ActualValue = if ($null -ne $actual) { $actual.ToString() } else { "NULL" }

                if ($expected -match "^n:(\d+)$") {
                    $result.Status = ($actual -eq [int]$Matches[1]) ? "PASS" : "FAIL"
                }
                elseif ($expected -match "^r:(.+)$") {
                    $result.Status = ($actual -match $Matches[1]) ? "PASS" : "FAIL"
                }
                elseif ($expected -match "^not r:") {
                    $result.Status = ($null -eq $actual) ? "PASS" : "FAIL"
                }
                else {
                    $result.Status = ($actual -eq $expected) ? "PASS" : "FAIL"
                }
            }
            catch [System.Management.Automation.ItemNotFoundException] {
                $result.Error = "Registry value not found"
            }
            catch {
                $result.Error = "Registry access error: $_"
            }
        }
        else {
            $result.Error = "Invalid rule format"
        }
    }
    catch {
        $result.Error = "Check processing error: $_"
    }

    return $result
}

# Main script execution
try {
    Write-Host "Loading YAML file..." -ForegroundColor Cyan
    $yamlContent = Get-Content "sca_win_audit.yml" -Raw
    $policy = ConvertFrom-Yaml $yamlContent

    if (-not $policy.checks -or $policy.checks.Count -eq 0) {
        throw "No checks found in YAML file"
    }

    Write-Host "Processing $($policy.checks.Count) checks..." -ForegroundColor Cyan
    $results = @()
    $count = 0

    foreach ($check in $policy.checks) {
        $count++
        Write-Progress -Activity "Processing Checks" -Status "$count/$($policy.checks.Count)" -PercentComplete ($count/$policy.checks.Count*100)
        
        $results += Process-SCACheck $check
    }

    # Generate HTML content
    $htmlRows = ""
    foreach ($result in $results) {
        $statusClass = switch ($result.Status) {
            "PASS" { "status-pass" }
            "FAIL" { "status-fail" }
            default { "status-error" }
        }

        $detailsId = "details-$($result.ID)"
        $htmlRow = @"
        <tr class="$statusClass">
            <td>$($result.ID)</td>
            <td>$($result.Title)</td>
            <td>$($result.Status)</td>
            <td>$($result.Expected)</td>
            <td>$($result.ActualValue)</td>
            <td><span class="toggle-details" onclick="toggleDetails('$detailsId')">Show Details</span></td>
        </tr>
        <tr id="$detailsId" class="details">
            <td colspan="6">
                <strong>Description:</strong> $($result.Description)<br>
                <strong>Compliance:</strong> $($result.Compliance)<br>
                <strong>Remediation:</strong> $($result.Remediation)<br>
                <strong>Error:</strong> $($result.Error)
            </td>
        </tr>
"@
        $htmlRows += $htmlRow
    }

    # Generate summary
    $passed = ($results | Where-Object { $_.Status -eq "PASS" }).Count
    $failed = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
    $errors = ($results | Where-Object { $_.Error }).Count

    # Build final HTML
    $htmlOutput = $htmlTemplate -replace "{DATE}", (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $htmlOutput = $htmlOutput -replace "{TOTAL}", $results.Count
    $htmlOutput = $htmlOutput -replace "{PASSED}", $passed
    $htmlOutput = $htmlOutput -replace "{FAILED}", $failed
    $htmlOutput = $htmlOutput -replace "{ERRORS}", $errors
    $htmlOutput = $htmlOutput -replace "{CONTENT}", $htmlRows

    # Save HTML file
    $outputFile = "SCA_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $htmlOutput | Out-File -FilePath $outputFile -Encoding UTF8

    Write-Host "`nHTML report saved to: $outputFile" -ForegroundColor Green

    # Show summary
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total checks: $($results.Count)"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Errors: $errors" -ForegroundColor Yellow

    # Open the HTML report automatically
    if (Test-Path $outputFile) {
        Start-Process $outputFile
    }
}
catch {
    Write-Host "`nFATAL ERROR: $_" -ForegroundColor Red
    exit 1
}