<#
.SYNOPSIS
    Processes Wazuh SCA Windows audit checks with full details in CSV output
.DESCRIPTION
    Enhanced version with complete field output including description and remediation
#>

# Load YAML module
try {
    Import-Module PowerShell-YAML -ErrorAction Stop
}
catch {
    Write-Host "ERROR: Install module first: Install-Module PowerShell-YAML -Force" -ForegroundColor Red
    exit 1
}

# Main processing function
function Process-SCACheck {
    param ($check)

    $result = [PSCustomObject]@{
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

                # Handle different expected value formats
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

    # Generate output filename with timestamp
    $outputFile = "SCA_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    # Export to CSV with all fields
    $results | Select-Object ID, Title, Description, Compliance, Status, ActualValue, Expected, Remediation, Error |
              Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

    Write-Host "`nResults saved to: $outputFile" -ForegroundColor Green

    # Show summary
    $passed = ($results | Where-Object { $_.Status -eq "PASS" }).Count
    $failed = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
    $errors = ($results | Where-Object { $_.Error }).Count

    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total checks: $($results.Count)"
    Write-Host "Passed: $passed" -ForegroundColor Green
    Write-Host "Failed: $failed" -ForegroundColor Red
    Write-Host "Errors: $errors" -ForegroundColor Yellow

    # Open the results file automatically
    if (Test-Path $outputFile) {
        Start-Process $outputFile
    }
}
catch {
    Write-Host "`nFATAL ERROR: $_" -ForegroundColor Red
    exit 1
}