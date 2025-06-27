using Microsoft.AspNetCore.Mvc;

namespace GithubSerilogDemo.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public sealed class LogController(ILogger<LogController> logger) : ControllerBase
    {
        private readonly ILogger<LogController> _logger = logger;

        [HttpPost]
        public IActionResult Log([FromBody] string logMessage)
        {
            _logger.LogDebug("Received log message: {LogMessage}", logMessage);
            _logger.LogInformation("Received log message: {LogMessage}", logMessage);
            _logger.LogWarning("Received log message: {LogMessage}", logMessage);
            _logger.LogError("Received log message: {LogMessage}", logMessage);
            return Ok();
        }
    }
}
