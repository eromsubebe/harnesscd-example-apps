# PCI DSS v4.0 - Requirement 6.2.4
# "Software engineering techniques or other methods are defined and in use by
#  software development personnel to prevent or mitigate common software attacks."
#
# Security scans cannot be conditionally skipped. A scan step with conditional
# execution (when clause or runtime condition) creates gaps where unscanned code
# could reach production. This violates the requirement that ALL changes are
# evaluated for security vulnerabilities.

package pci_dss.req6_no_conditional_scan_bypass

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
security_scan_step_types := [
	"Security", "AquaTrivy", "Veracode", "SonarQube", "Wiz", "Snyk",
	"Checkmarx", "Prisma", "BlackDuck", "WhiteSource", "Mend", "Fortify",
]

# --- POLICY RULES ---

# Deny security scan steps with conditional execution based on stage status
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in security_scan_step_types

	step.when
	step.when.stageStatus != "Success"

	msg := sprintf(
		"PCI DSS 6.2.4 Violation: Security scan step '%s' in stage '%s' has conditional execution (when: %s). Security scans must run unconditionally on every pipeline execution — conditional bypass allows unscanned code to reach the CDE.",
		[step.name, stage.name, step.when.stageStatus],
	)
}

# Deny security scan steps gated by runtime expressions/variables
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in security_scan_step_types

	step.when
	step.when.condition

	msg := sprintf(
		"PCI DSS 6.2.4 Violation: Security scan step '%s' in stage '%s' has a conditional expression ('%s'). Vulnerability scans must not be gated by runtime variables — every code change must be scanned regardless of branch, trigger, or input.",
		[step.name, stage.name, step.when.condition],
	)
}

# Deny SecurityTests stages with conditional execution
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "SecurityTests"

	stage.when
	stage.when.condition

	msg := sprintf(
		"PCI DSS 6.2.4 Violation: Security testing stage '%s' has conditional execution ('%s'). Security testing stages must run on every pipeline execution to ensure continuous vulnerability assessment.",
		[stage.name, stage.when.condition],
	)
}
