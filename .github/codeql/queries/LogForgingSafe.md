# Log entries created from user input (Safe Serilog Configuration)

## Overview

If unsanitized user input is written to a log entry, a malicious user may be able to forge new log entries.

Forgery can occur if a user provides some input with characters that are interpreted when the log output is displayed. If the log is displayed as a plain text file, then newline characters can be used by a malicious user. If the log is displayed as HTML, then arbitrary HTML may be included to spoof log entries.

However, when Serilog is configured with **exclusively safe** formatters like `RenderedCompactJsonFormatter`, log entries are properly escaped and structured as JSON, preventing log forging attacks. This query recognizes such safe configurations and does not report vulnerabilities in those cases.

**Important**: This query uses a conservative approach and only exempts logging when ALL Serilog outputs use safe formatting. Mixed configurations (safe + unsafe) will still report vulnerabilities.

## Recommendation

User input should be suitably encoded before it is logged, or a safe logging configuration should be used.

### General Recommendations:
- If the log entries are plain text, then line breaks should be removed from user input, using `String.Replace` or similar. Care should also be taken that user input is clearly marked in log entries, and that a malicious user cannot cause confusion in other ways.
- For log entries that will be displayed in HTML, user input should be HTML encoded using `HttpServerUtility.HtmlEncode` or similar before being logged, to prevent forgery and other forms of HTML injection.

### Safe Serilog Configuration:
When using Serilog with `RenderedCompactJsonFormatter`, log entries are automatically escaped and formatted as structured JSON. This prevents log forging attacks because:
- Special characters (including newlines) are properly escaped in JSON format
- Log structure is preserved and cannot be manipulated by user input
- Each log entry is a complete, parseable JSON object

Configure Serilog with safe formatting in your `Program.cs`:
```csharp
builder.Host.UseSerilog((context, _, loggerConfiguration) =>
{
    loggerConfiguration
        .ReadFrom.Configuration(builder.Configuration)
        .Enrich.FromLogContext()
        .WriteTo.Console(formatter: new RenderedCompactJsonFormatter());
});
```

## Example

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Formatting.Compact;

// Program.cs - Safe Serilog Configuration
public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Configure Serilog with safe JSON formatter
        builder.Host.UseSerilog((context, _, loggerConfiguration) =>
        {
            loggerConfiguration
                .ReadFrom.Configuration(builder.Configuration)
                .Enrich.FromLogContext()
                .WriteTo.Console(formatter: new RenderedCompactJsonFormatter()); // Safe formatter
        });

        builder.Services.AddControllers();
        var app = builder.Build();
        app.MapControllers();
        app.Run();
    }
}

// Controller with logging
[ApiController]
[Route("[controller]")]
public class LogController : ControllerBase
{
    private readonly ILogger<LogController> _logger;

    public LogController(ILogger<LogController> logger)
    {
        _logger = logger;
    }

    [HttpPost]
    public IActionResult ProcessRequest([FromBody] string userInput)
    {
        // GOOD: Safe when using RenderedCompactJsonFormatter
        // The formatter automatically escapes special characters and structures as JSON
        _logger.LogInformation("User input received: {UserInput}", userInput);
        
        // GOOD: Structured logging with safe formatter
        _logger.LogWarning("Processing request from user: {UserInput} at {Timestamp}", 
                          userInput, DateTime.UtcNow);

        return Ok("Processed");
    }
}

// Example without safe formatter (vulnerable)
public class UnsafeLoggingExample
{
    private readonly ILogger<UnsafeLoggingExample> _logger;

    public void ProcessRequest(string userInput)
    {
        // BAD: Without safe formatter, user input could contain newlines or control characters
        // that could forge log entries when using plain text formatters
        _logger.LogInformation("User input: " + userInput);
        
        // GOOD: Manual sanitization (alternative approach)
        _logger.LogInformation("User input: {UserInput}", 
                              userInput.Replace(Environment.NewLine, "").Replace("\r", "").Replace("\n", ""));
    }
}
```

### Output Comparison

**Unsafe logging output (plain text formatter):**
```
2024-01-15 10:30:00 [INF] User input: legitimate input
malicious log entry injected
2024-01-15 10:30:00 [INF] User input: normal input
```

**Safe logging output (RenderedCompactJsonFormatter):**
```json
{"@t":"2024-01-15T10:30:00.0000000Z","@mt":"User input: {UserInput}","UserInput":"legitimate input\nmalicious log entry injected"}
{"@t":"2024-01-15T10:30:00.0000000Z","@mt":"User input: {UserInput}","UserInput":"normal input"}
```

In the safe output, newlines and special characters are properly escaped within the JSON structure, preventing log forging.

## Detection Logic

This query identifies safe Serilog configurations by:

1. **Detecting Safe Formatter Usage**: Looking for `RenderedCompactJsonFormatter` object creation
2. **Verifying Serilog Registration**: Confirming Serilog is registered via `UseSerilog()` method calls
3. **Sanitizing ILogger Calls**: When both conditions are met, treating ILogger method arguments as safe

The query will NOT report log forging vulnerabilities for applications that meet these criteria, significantly reducing false positives in properly configured Serilog applications.

## References

- OWASP: [Log Injection](https://www.owasp.org/index.php/Log_Injection)
- Serilog: [Formatting Output](https://serilog.readthedocs.io/en/stable/formatting-output/)
- Serilog: [Compact JSON Formatter](https://github.com/serilog/serilog-formatting-compact)
