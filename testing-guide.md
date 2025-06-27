# Testing the Log Endpoint

## Using HTTP File (VS Code REST Client Extension)
You can use the provided `test-logs.http` file with the VS Code REST Client extension:

```http
### Test Log Endpoint
POST http://localhost:5000/log
Content-Type: application/json

"This is a test log message"
```

## Using PowerShell
Run the provided PowerShell script `test-logs.ps1`:

```powershell
$uri = "http://localhost:5000/log"
$body = '"This is a test log message"'
$headers = @{
    "Content-Type" = "application/json"
}

try {
    $response = Invoke-WebRequest -Uri $uri -Method Post -Body $body -Headers $headers
    Write-Host "Status Code: $($response.StatusCode)"
    Write-Host "Response: $($response.Content)"
} catch {
    Write-Host "Error: $_"
}
```

## Using curl
You can also use curl from the command line:

```bash
curl -X POST http://localhost:5000/log -H "Content-Type: application/json" -d "\"This is a test log message\""
```

## Using Postman
1. Set the request type to POST
2. Enter the URL: http://localhost:5000/log
3. Go to "Body" tab, select "raw", and choose "JSON" from the dropdown
4. Enter: "This is a test log message" (with the quotes)
5. Click "Send"

## Server Output
When you send a request to the endpoint, you should see logs like these in the server console:

```json
{"@t":"2025-06-27T16:23:48.3375178Z","@m":"Received log message: \"This is a test log message\"","@l":"Debug","LogMessage":"This is a test log message","SourceContext":"GithubSerilogDemo.Controllers.LogController"}
{"@t":"2025-06-27T16:23:48.3379950Z","@m":"Received log message: \"This is a test log message\"","LogMessage":"This is a test log message","SourceContext":"GithubSerilogDemo.Controllers.LogController"}
{"@t":"2025-06-27T16:23:48.3381172Z","@m":"Received log message: \"This is a test log message\"","@l":"Warning","LogMessage":"This is a test log message","SourceContext":"GithubSerilogDemo.Controllers.LogController"}
{"@t":"2025-06-27T16:23:48.3382608Z","@m":"Received log message: \"This is a test log message\"","@l":"Error","LogMessage":"This is a test log message","SourceContext":"GithubSerilogDemo.Controllers.LogController"}
```

## Starting the Server
To start the server, run:

```bash
cd "c:\repos\cmr-projects\github-demo-serilog-main"
dotnet run
```
