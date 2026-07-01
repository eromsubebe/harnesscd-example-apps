# NIST CSF 2.0 - DE.AE (Adverse Event Analysis)
# Maps to: DE.AE-06 — Information on adverse events is provided to authorized staff
#   and tools.
# Maps to: RS.AN-03 — Analysis is performed to determine what has taken place during
#   an incident and the root cause of the incident.
#
# Guidance: Organizations must not suppress or ignore indicators of adverse events.
# When a vulnerability scan detects critical/high-severity findings, the pipeline
# must halt — not continue silently. Setting failure strategies to "Ignore" or
# "MarkAsSuccess" on security scan steps effectively suppresses adverse event
# indicators, violating the requirement to analyze and respond to detected threats.

package nist.de_ae_no_scan_suppression

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Security scan step types whose failures must not be suppressed
vulnerability_scan_step_types := ["AquaTrivy", "Wiz", "Snyk", "Prisma", "Security", "Veracode", "BlackDuck", "WhiteSource", "Mend", "Checkmarx", "SonarQube", "Fortify"]

# Failure strategy actions that suppress scan findings
suppressing_actions := ["Ignore", "MarkAsSuccess"]

# --- POLICY RULES ---

# Deny security scan steps with failure strategy set to Ignore
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in vulnerability_scan_step_types

	step.failureStrategies[_].onFailure.action.type == "Ignore"

	msg := sprintf(
		"NIST CSF DE.AE-06 Violation: Security scan step '%s' in stage '%s' has failure strategy set to 'Ignore'. Adverse event indicators from vulnerability scans must never be suppressed — findings must halt the pipeline or trigger escalation.",
		[step.name, stage.name],
	)
}

# Deny security scan steps with failure strategy set to MarkAsSuccess
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in vulnerability_scan_step_types

	step.failureStrategies[_].onFailure.action.type == "MarkAsSuccess"

	msg := sprintf(
		"NIST CSF DE.AE-06 Violation: Security scan step '%s' in stage '%s' has failure strategy set to 'MarkAsSuccess'. Vulnerability findings must not be masked as successful — this suppresses adverse event indicators and prevents proper incident analysis.",
		[step.name, stage.name],
	)
}

# Deny SecurityTests stages with suppressing failure strategies
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "SecurityTests"

	action := stage.failureStrategies[_].onFailure.action.type
	action in suppressing_actions

	msg := sprintf(
		"NIST CSF DE.AE-06 Violation: Security stage '%s' has failure strategy set to '%s'. Security test stages must block the pipeline on failure to ensure adverse events are analyzed and addressed, not silently ignored.",
		[stage.name, action],
	)
}
