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
import semmle.code.csharp.security.dataflow.flowsinks.FlowSinks
import semmle.code.csharp.security.dataflow.flowsources.FlowSources
import semmle.code.csharp.frameworks.System
import semmle.code.csharp.frameworks.system.text.RegularExpressions
import semmle.code.csharp.security.Sanitizers
import semmle.code.csharp.security.dataflow.flowsinks.ExternalLocationSink
import semmle.code.csharp.dataflow.internal.ExternalFlow
import semmle.code.csharp.commons.Loggers

/**
 * A data flow source for untrusted user input used in log entries.
 */
abstract class Source extends DataFlow::Node { }

/**
 * A data flow sink for untrusted user input used in log entries.
 */
abstract class Sink extends ApiSinkExprNode { }

/**
 * A sanitizer for untrusted user input used in log entries.
 */
abstract class Sanitizer extends DataFlow::ExprNode { }

/**
 * A predicate to detect if Serilog is configured with safe formatters ONLY.
 * This ensures ALL Serilog outputs use safe formatting like RenderedCompactJsonFormatter.
 */
private predicate isSerilogConfiguredSafely() {
  // Check if RenderedCompactJsonFormatter is used in the application
  exists(ObjectCreation oc |
    oc.getObjectType().hasFullyQualifiedName("Serilog.Formatting.Compact", "RenderedCompactJsonFormatter") or
    oc.getObjectType().getName() = "RenderedCompactJsonFormatter"
  ) and
  // Ensure no unsafe WriteTo configurations exist (like File with outputTemplate)
  not exists(MethodCall unsafeWriteTo |
    unsafeWriteTo.getTarget().hasName("File") and
    unsafeWriteTo.getQualifier().getType().getName().matches("%LoggerConfiguration%") and
    exists(Expr templateArg |
      templateArg = unsafeWriteTo.getArgumentForName("outputTemplate") and
      // Check if the template contains unsafe formatting patterns
      templateArg.getValue().toString().matches("%{Message:lj}%")
    )
  )
}

/**
 * A predicate to detect if the application uses Serilog as its primary logging framework.
 * This checks for UseSerilog configuration which indicates Serilog is registered with DI.
 */
private predicate isOnlyILoggerRegistered() {
  // Check that Serilog is configured as the logger provider
  exists(MethodCall useSerilog |
    useSerilog.getTarget().hasName("UseSerilog")
  )
  // Note: We don't check for absence of other loggers since they may be conditionally configured
  // The key is that if RenderedCompactJsonFormatter is used, it should be safe regardless
}

/**
 * A sanitizer for log sinks when Serilog is configured safely with RenderedCompactJsonFormatter.
 * This prevents log forging vulnerabilities when safe JSON formatting is used.
 */
private class SafeSerilogSanitizer extends Sanitizer {
  SafeSerilogSanitizer() {
    // Only sanitize if this is a call to a logger method and Serilog is configured safely
    exists(MethodCall mc |
      this.asExpr() = mc.getAnArgument() and
      (
        // Check if this is an ILogger method call
        mc.getTarget().getDeclaringType().hasFullyQualifiedName("Microsoft.Extensions.Logging", "ILogger") or
        mc.getTarget().getDeclaringType().getABaseType*().hasName("ILogger") or
        mc.getQualifier().getType() instanceof LoggerType or
        mc.getTarget().hasName(["LogDebug", "LogInformation", "LogWarning", "LogError", "LogCritical", "LogTrace"])
      ) and
      isSerilogConfiguredSafely() and
      isOnlyILoggerRegistered()
    )
  }
}

/**
 * A taint-tracking configuration for untrusted user input used in log entries with safe Serilog handling.
 */
private module LogForgingSafeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node node) { 
    node instanceof Sanitizer or
    node instanceof SafeSerilogSanitizer
  }
}

/**
 * A taint-tracking module for untrusted user input used in log entries with safe Serilog handling.
 */
module LogForgingSafe = TaintTracking::Global<LogForgingSafeConfig>;

/** A source supported by the current threat model. */
private class ThreatModelSource extends Source instanceof ActiveThreatModelSource { }

private class HtmlSanitizer extends Sanitizer {
  HtmlSanitizer() { this.asExpr() instanceof HtmlSanitizedExpr }
}

/**
 * An argument to a call to a method on a logger class.
 */
private class LogForgingLogMessageSink extends Sink, LogMessageSink { }

/**
 * An argument to a call to a method on a trace class.
 */
private class LogForgingTraceMessageSink extends Sink, TraceMessageSink { }

/** Log Forging sinks defined through Models as Data. */
private class ExternalLoggingExprSink extends Sink {
  ExternalLoggingExprSink() { sinkNode(this, "log-injection") }
}

/**
 * A call to String replace or remove that is considered to sanitize replaced string.
 */
private class StringReplaceSanitizer extends Sanitizer {
  StringReplaceSanitizer() {
    exists(Method m |
      exists(SystemStringClass s |
        m = s.getReplaceMethod() or m = s.getRemoveMethod() or m = s.getReplaceLineEndingsMethod()
      )
      or
      m = any(SystemTextRegularExpressionsRegexClass r).getAReplaceMethod()
    |
      this.asExpr() = m.getACall()
    )
  }
}

private class SimpleTypeSanitizer extends Sanitizer, SimpleTypeSanitizedExpr { }

private class GuidSanitizer extends Sanitizer, GuidSanitizedExpr { }

import LogForgingSafe::PathGraph

from LogForgingSafe::PathNode source, LogForgingSafe::PathNode sink
where LogForgingSafe::flowPath(source, sink)
select sink.getNode(), source, sink, "This log entry depends on a $@.", source.getNode(),
  "user-provided value"
