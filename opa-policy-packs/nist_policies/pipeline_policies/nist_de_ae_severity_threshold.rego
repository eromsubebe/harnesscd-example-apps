# NIST CSF 2.0 - DE.AE (Adverse Event Analysis)
# Maps to: DE.AE-02 — Potentially adverse events are analyzed to better understand
#   associated activities.
# Maps to: DE.AE-03 — Information is correlated from multiple sources.
# Maps to: ID.RA-01 — Vulnerabilities in assets are identified, validated, and recorded.
#
# Guidance: When adverse events (vulnerabilities) are detected, organizations must
# analyze their severity and take appropriate action. This policy ensures that
# security scan steps are configured with a severity threshold so that critical
# and high-severity CVEs automatically block the pipeline. Scans without thresholds
# produce informational findings that are never acted upon, violating the requirement
# to respond to identified risks.

package nist.de_ae_severity_threshold

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Security scan step types that must have severity thresholds configured
vulnerability_scan_step_types := ["AquaTrivy", "Wiz", "Snyk", "Prisma", "Security", "Veracode", "BlackDuck", "WhiteSource", "Mend", "Checkmarx"]

# Valid severity thresholds (these indicate the step is configured to block)
valid_severity_levels := ["Critical", "High", "Medium"]

# --- POLICY RULES ---

# Deny security scan steps without a fail_on_severity configuration
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in vulnerability_scan_step_types

	not step.spec.settings.fail_on_severity

	msg := sprintf(
		"NIST CSF DE.AE-02 Violation: Security scan step '%s' in stage '%s' has no severity threshold configured (fail_on_severity). Adverse event analysis requires that scans block the pipeline when vulnerabilities exceed the defined severity level.",
		[step.name, stage.name],
	)
}

# Deny security scan steps with severity threshold set too low (informational only)
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in vulnerability_scan_step_types

	step.spec.settings.fail_on_severity
	not step.spec.settings.fail_on_severity in valid_severity_levels

	msg := sprintf(
		"NIST CSF DE.AE-02 Violation: Security scan step '%s' in stage '%s' has severity threshold set to '%s'. Threshold must be one of: %s to ensure critical vulnerabilities block deployment.",
		[step.name, stage.name, step.spec.settings.fail_on_severity, concat(", ", valid_severity_levels)],
	)
}
