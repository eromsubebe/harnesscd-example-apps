# SOC 2 CC6.8 - Malicious Software Prevention
# Rule: Are pipelines blocked from deploying if critical/high CVEs are found?
# Ensures security scan steps are configured to fail the pipeline on critical or
# high severity findings, preventing vulnerable artifacts from reaching production.

package pipeline.block_deploy_on_critical_cves

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Security scan step types that must block on critical/high findings
security_scan_step_types := ["AquaTrivy", "Wiz", "Snyk", "Prisma", "Security", "Veracode", "SonarQube", "Checkmarx", "BlackDuck", "WhiteSource", "Mend"]

# Failure strategy actions that effectively suppress scan findings
suppressing_actions := ["Ignore", "MarkAsSuccess"]

# --- POLICY RULES ---

# Deny security scan steps with failure strategy set to Ignore
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in security_scan_step_types

	step.failureStrategies[_].onFailure.action.type == "Ignore"

	msg := sprintf(
		"SOC 2 CC6.8 Violation: Security scan step '%s' in stage '%s' has failure strategy set to 'Ignore'. Pipelines must block deployment when critical/high CVEs are found — scan failures must not be suppressed.",
		[step.name, stage.name],
	)
}

# Deny security scan steps with failure strategy set to MarkAsSuccess
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in security_scan_step_types

	step.failureStrategies[_].onFailure.action.type == "MarkAsSuccess"

	msg := sprintf(
		"SOC 2 CC6.8 Violation: Security scan step '%s' in stage '%s' has failure strategy set to 'MarkAsSuccess'. Pipelines must block deployment when critical/high CVEs are found — scan results must not be marked as successful on failure.",
		[step.name, stage.name],
	)
}

# Deny security scan stages with failure strategy set to Ignore
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "SecurityTests"

	stage.failureStrategies[_].onFailure.action.type == "Ignore"

	msg := sprintf(
		"SOC 2 CC6.8 Violation: Security stage '%s' has failure strategy set to 'Ignore'. Security scan stages must halt the pipeline on critical/high findings to prevent deployment of vulnerable artifacts.",
		[stage.name],
	)
}

# Deny security scan stages with failure strategy set to MarkAsSuccess
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "SecurityTests"

	stage.failureStrategies[_].onFailure.action.type == "MarkAsSuccess"

	msg := sprintf(
		"SOC 2 CC6.8 Violation: Security stage '%s' has failure strategy set to 'MarkAsSuccess'. Security scan stages must halt the pipeline on critical/high findings to prevent deployment of vulnerable artifacts.",
		[stage.name],
	)
}

# Deny deployment stages that proceed without a preceding security stage having a blocking failure strategy
deny[msg] {
	some i
	input.pipeline.stages[i].stage.type == "Deployment"

	has_preceding_security_stage(i)
	not preceding_security_stage_blocks(i)

	msg := sprintf(
		"SOC 2 CC6.8 Violation: Deployment stage '%s' is preceded by a security scan stage that does not have a blocking failure strategy. Security stages must be configured to stop the pipeline on critical/high CVE findings.",
		[input.pipeline.stages[i].stage.name],
	)
}

# --- HELPER RULES ---

has_preceding_security_stage(deploy_index) if {
	some j
	j < deploy_index
	input.pipeline.stages[j].stage.type == "SecurityTests"
}

preceding_security_stage_blocks(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	stage.type == "SecurityTests"
	stage.failureStrategies
	not stage_suppresses_failure(stage)
}

stage_suppresses_failure(stage) if {
	action := stage.failureStrategies[_].onFailure.action.type
	action in suppressing_actions
}
