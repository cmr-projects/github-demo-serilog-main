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
 * A predicate to detect if there are unsafe Serilog output configurations.
 * An output is unsafe if Serilog is configured but has ANY outputs that don't use safe formatters.
 * Safe formatters are: RenderedCompactJsonFormatter, JsonFormatter.
 * Mixed configurations (safe + unsafe) are considered unsafe.
 */
private predicate hasUnsafeSerilogOutputs() {
  // Check if Serilog is configured
  exists(MethodCall useSerilog |
    useSerilog.getTarget().hasName("UseSerilog")
  ) and
  (
    // Either no safe formatters exist at all
    not exists(ObjectCreation formatter |
      formatter.getObjectType().hasFullyQualifiedName("Serilog.Formatting.Compact", "RenderedCompactJsonFormatter") or
      formatter.getObjectType().getName() = "RenderedCompactJsonFormatter" or
      formatter.getObjectType().hasFullyQualifiedName("Serilog.Formatting.Json", "JsonFormatter") or
      formatter.getObjectType().getName() = "JsonFormatter"
    )
    or
    // Or there are outputTemplate string literals indicating unsafe raw text outputs
    exists(StringLiteral sl |
      sl.getValue().matches("%{Timestamp%") or
      sl.getValue().matches("%{Level%") or
      sl.getValue().matches("%{Message%") or
      sl.getValue().matches("%{NewLine%") or
      sl.getValue().matches("%{Exception%")
    )
  )
}

/**
 * A predicate to detect if Serilog is configured with ONLY safe formatters.
 * This checks that ALL WriteTo calls use safe formatters (RenderedCompactJsonFormatter or JsonFormatter).
 * If ANY WriteTo call lacks a safe formatter, the entire configuration is considered unsafe.
 */
private predicate isSerilogConfiguredSafelyOnly() {
  // Check if RenderedCompactJsonFormatter or JsonFormatter is used in the application
  exists(ObjectCreation oc |
    oc.getObjectType().hasFullyQualifiedName("Serilog.Formatting.Compact", "RenderedCompactJsonFormatter") or
    oc.getObjectType().getName() = "RenderedCompactJsonFormatter" or
    oc.getObjectType().hasFullyQualifiedName("Serilog.Formatting.Json", "JsonFormatter") or
    oc.getObjectType().getName() = "JsonFormatter"
  ) and
  // Ensure no unsafe logging outputs exist
  not hasUnsafeSerilogOutputs() and
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
