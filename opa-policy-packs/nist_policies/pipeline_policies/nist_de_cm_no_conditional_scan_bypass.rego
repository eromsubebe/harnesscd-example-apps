# NIST CSF 2.0 - DE.CM (Continuous Monitoring)
# Maps to: DE.CM-01 — Networks and network services are monitored to find potentially
#   adverse events.
# Maps to: PR.PS-02 — Software is maintained, replaced, and removed commensurate
#   with risk.
#
# Guidance: Continuous monitoring must be applied consistently — security scans cannot
# be conditionally bypassed. A scan step with conditional execution (e.g., only run
# if a variable is set, or only on certain branches) creates gaps in vulnerability
# detection. This policy ensures security scan steps do not have conditional execution
# that could skip them, guaranteeing every pipeline run performs vulnerability assessment.

package nist.de_cm_no_conditional_scan_bypass

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Security scan step types that must not be conditionally skipped
vulnerability_scan_step_types := ["AquaTrivy", "Wiz", "Snyk", "Prisma", "Security", "Veracode", "BlackDuck", "WhiteSource", "Mend", "Checkmarx", "SonarQube", "Fortify"]

# --- POLICY RULES ---

# Deny security scan steps with conditional execution (when clause)
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in vulnerability_scan_step_types

	step.when
	step.when.stageStatus != "Success"

	msg := sprintf(
		"NIST CSF DE.CM-01 Violation: Security scan step '%s' in stage '%s' has conditional execution configured (when: %s). Vulnerability scans must run unconditionally — conditional execution creates monitoring gaps that allow unscanned artifacts to reach deployment.",
		[step.name, stage.name, step.when.stageStatus],
	)
}

# Deny security scan steps with condition set to only run on specific inputs/variables
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in vulnerability_scan_step_types

	step.when
	step.when.condition

	msg := sprintf(
		"NIST CSF DE.CM-01 Violation: Security scan step '%s' in stage '%s' has a conditional expression ('%s'). Vulnerability scans must not be gated by runtime conditions — continuous monitoring requires scans to execute on every pipeline run.",
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
		"NIST CSF DE.CM-01 Violation: Security stage '%s' has conditional execution ('%s'). Security testing stages must run on every pipeline execution — conditional bypass violates continuous monitoring requirements.",
		[stage.name, stage.when.condition],
	)
}
