# PCI DSS v4.0 - Requirement 6.2.4 / 6.5.5
# "Changes to all software components are evaluated to ensure the changes do not
#  introduce new security vulnerabilities."
#
# Security scan steps must not have their results suppressed via failure strategies.
# Setting a scan step to "Ignore" or "MarkAsSuccess" on failure effectively hides
# vulnerabilities and allows insecure code into production — violating the requirement
# that all changes are evaluated for security impact.

package pci_dss.req6_no_scan_suppression

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
security_scan_step_types := [
	"Security", "AquaTrivy", "Veracode", "SonarQube", "Wiz", "Snyk",
	"Checkmarx", "Prisma", "BlackDuck", "WhiteSource", "Mend", "Fortify",
]

suppressing_actions := ["Ignore", "MarkAsSuccess"]

# --- POLICY RULES ---

# Deny security scan steps with failure strategy that suppresses findings
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in security_scan_step_types

	action := step.failureStrategies[_].onFailure.action.type
	action in suppressing_actions

	msg := sprintf(
		"PCI DSS 6.2.4 Violation: Security scan step '%s' in stage '%s' has failure strategy set to '%s'. Vulnerability findings must never be suppressed — scan failures must halt the pipeline or trigger manual intervention.",
		[step.name, stage.name, action],
	)
}

# Deny SecurityTests stages with suppressing failure strategies
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "SecurityTests"

	action := stage.failureStrategies[_].onFailure.action.type
	action in suppressing_actions

	msg := sprintf(
		"PCI DSS 6.2.4 Violation: Security testing stage '%s' has failure strategy set to '%s'. Security test stages must block the pipeline on failure to ensure vulnerabilities are addressed before deployment.",
		[stage.name, action],
	)
}

# Deny scan steps with severity threshold set too low or missing
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in security_scan_step_types

	not step.spec.settings.fail_on_severity

	msg := sprintf(
		"PCI DSS 6.5.5 Violation: Security scan step '%s' in stage '%s' has no severity threshold (fail_on_severity). Scans must be configured to block the pipeline when vulnerabilities at or above 'High' severity are detected.",
		[step.name, stage.name],
	)
}
