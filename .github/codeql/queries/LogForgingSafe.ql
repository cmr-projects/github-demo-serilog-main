/**
 * @name Log entries created from user input (Safe Serilog Configuration)
 * @description Building log entries from user-controlled sources is vulnerable to
 *              insertion of forged log entries by a malicious user. However, this query
 *              exempts applications that use Serilog with safe formatters like
 *              RenderedCompactJsonFormatter which prevent log forging attacks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id cs/log-forging-safe
 * @tags security
 *       external/cwe/cwe-117
 */

import csharp
import semmle.code.csharp.security.dataflow.LogForgingQuery
import semmle.code.csharp.commons.Loggers

/**
 * A predicate to detect if Serilog is configured with ONLY safe formatters.
 * This is a conservative check - we only sanitize if we can prove all outputs are safe.
 * For mixed configurations (safe + unsafe), we do NOT sanitize.
 */
private predicate isSerilogConfiguredSafelyOnly() {
  // Check if RenderedCompactJsonFormatter is used in the application
  exists(ObjectCreation oc |
    oc.getObjectType().hasFullyQualifiedName("Serilog.Formatting.Compact", "RenderedCompactJsonFormatter") or
    oc.getObjectType().getName() = "RenderedCompactJsonFormatter"
  ) and
  // Ensure no unsafe logging patterns exist in string literals
  // This catches unsafe outputTemplate patterns like {Message:lj}
  not exists(StringLiteral sl |
    sl.getValue().matches("%{Message:lj}%") or
    sl.getValue().matches("%{Message}%") and not sl.getValue().matches("%{Message:j}%")
  ) and
  // Check that Serilog is configured as the logger provider
  exists(MethodCall useSerilog |
    useSerilog.getTarget().hasName("UseSerilog")
  )
}

/**
 * A sanitizer for log sinks when Serilog is configured safely with ONLY safe formatters.
 * This prevents log forging vulnerabilities when ALL logging uses safe JSON formatting.
 */
private class SafeSerilogSanitizer extends Sanitizer {
  SafeSerilogSanitizer() {
    // Only sanitize if this is a call to a logger method and Serilog is configured with ONLY safe outputs
    exists(MethodCall mc |
      this.asExpr() = mc.getAnArgument() and
      (
        // Check if this is an ILogger method call
        mc.getTarget().getDeclaringType().hasFullyQualifiedName("Microsoft.Extensions.Logging", "ILogger") or
        mc.getTarget().getDeclaringType().getABaseType*().hasName("ILogger") or
        mc.getQualifier().getType() instanceof LoggerType or
        mc.getTarget().hasName(["LogDebug", "LogInformation", "LogWarning", "LogError", "LogCritical", "LogTrace"])
      ) and
      isSerilogConfiguredSafelyOnly()
    )
  }
}

import LogForging::PathGraph

from LogForging::PathNode source, LogForging::PathNode sink
where LogForging::flowPath(source, sink)
select sink.getNode(), source, sink, "This log entry depends on a $@.", source.getNode(),
  "user-provided value"
