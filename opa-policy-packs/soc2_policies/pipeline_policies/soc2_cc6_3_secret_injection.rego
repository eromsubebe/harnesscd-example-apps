# SOC 2 CC6.3 - Logical and Physical Access Controls
# Ensures secrets are passed to pipeline steps via secure injection mechanisms
# and are not exposed as plaintext in environment variables or logs.

package soc2.cc6_3_secret_injection

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Patterns indicating inline secret expressions that should use type "Secret"
secret_expression_patterns := [
	"<+secrets.getValue",
	"<+secrets.get",
]

# Patterns indicating hardcoded credentials in variable values
hardcoded_secret_patterns := [
	"password",
	"BEGIN RSA PRIVATE KEY",
	"BEGIN PRIVATE KEY",
	"AKIA",
	"sk-",
	"ghp_",
	"glpat-",
]

# --- POLICY RULES ---

# Deny pipeline variables that contain secret expressions but are not typed as Secret
deny[msg] {
	variable := input.pipeline.variables[_]
	variable.type != "Secret"

	some pattern in secret_expression_patterns
	contains(variable.value, pattern)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Pipeline variable '%s' references a secret via expression but is not typed as 'Secret'. Secrets must use the Secret variable type to ensure secure injection and masking in logs.",
		[variable.name],
	)
}

# Deny pipeline variables that appear to contain hardcoded credentials
deny[msg] {
	variable := input.pipeline.variables[_]
	variable.type != "Secret"

	some pattern in hardcoded_secret_patterns
	contains(variable.value, pattern)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Pipeline variable '%s' appears to contain a hardcoded credential. Secrets must be stored in a secret manager and injected securely, never as plaintext values.",
		[variable.name],
	)
}

# Deny stage variables that contain secret expressions but are not typed as Secret
deny[msg] {
	stage := input.pipeline.stages[_].stage
	variable := stage.variables[_]
	variable.type != "Secret"

	some pattern in secret_expression_patterns
	contains(variable.value, pattern)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Stage '%s' variable '%s' references a secret but is not typed as 'Secret'. Non-secret variables are not masked in logs, risking credential exposure.",
		[stage.name, variable.name],
	)
}

# Deny stage variables that appear to contain hardcoded credentials
deny[msg] {
	stage := input.pipeline.stages[_].stage
	variable := stage.variables[_]
	variable.type != "Secret"

	some pattern in hardcoded_secret_patterns
	contains(variable.value, pattern)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Stage '%s' variable '%s' appears to contain a hardcoded credential. Secrets must be injected via secure mechanisms, not embedded as plaintext.",
		[stage.name, variable.name],
	)
}

# Deny shell steps that echo environment variables containing "secret" or "password"
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	step.spec.source.spec.script

	contains(step.spec.source.spec.script, "echo $")
	contains(lower(step.spec.source.spec.script), "secret")

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Shell step '%s' in stage '%s' may be printing secrets to stdout via echo. Secrets must never be written to logs in plaintext.",
		[step.name, stage.name],
	)
}

# Deny shell steps that echo password variables
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	step.spec.source.spec.script

	contains(step.spec.source.spec.script, "echo $")
	contains(lower(step.spec.source.spec.script), "password")

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Shell step '%s' in stage '%s' may be printing passwords to stdout via echo. Secrets must never be written to logs in plaintext.",
		[step.name, stage.name],
	)
}

# Deny shell steps that use printenv or env commands which dump all environment variables
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	step.spec.source.spec.script

	contains(step.spec.source.spec.script, "printenv")

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Shell step '%s' in stage '%s' uses 'printenv' which may dump secrets to logs. Secrets must not be exposed in pipeline output.",
		[step.name, stage.name],
	)
}

# Deny shell steps that use set -x with secret references (expands secrets in trace output)
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	step.spec.source.spec.script

	contains(step.spec.source.spec.script, "set -x")
	contains(lower(step.spec.source.spec.script), "secret")

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Shell step '%s' in stage '%s' enables command tracing (set -x) while referencing secrets. Trace output will expose secret values in logs.",
		[step.name, stage.name],
	)
}
