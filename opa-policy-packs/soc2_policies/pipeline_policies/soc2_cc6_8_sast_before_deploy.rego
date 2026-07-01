# SOC 2 CC6.8 - Malicious Software Prevention
# Rule: Is static analysis required before a pipeline can deploy to production?
# Requires every pipeline to run a Static Application Security Testing (SAST) scan
# before any deployment stage to detect code-level vulnerabilities and malicious patterns.

package pipeline.soc2_cc6_8_sast_before_deploy

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Step types that qualify as SAST/static analysis scans
sast_step_types := ["Security", "Veracode", "SonarQube", "Checkmarx", "Fortify", "Semgrep", "CodeQL"]

# Stage types considered as containing SAST scans
scan_stage_types := ["CI", "Build", "SecurityTests"]

# --- POLICY RULES ---

# Deny deployment stages that have no preceding SAST/static analysis scan
deny[msg] {
	some i
	input.pipeline.stages[i].stage.type == "Deployment"

	not has_preceding_sast_scan(i)

	msg := sprintf(
		"SOC 2 CC6.8 Violation: Deployment stage '%s' has no preceding static analysis (SAST) scan. Every pipeline must run static code analysis before deploying to detect code-level vulnerabilities and malicious patterns.",
		[input.pipeline.stages[i].stage.name],
	)
}

# --- HELPER RULES ---

has_preceding_sast_scan(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	stage.type in scan_stage_types
	has_sast_step(stage)
}

has_sast_step(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in sast_step_types
}

has_sast_step(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "sast")
}

has_sast_step(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "static")
	contains(lower(step.name), "analysis")
}

has_sast_step(stage) if {
	template_ref := stage.spec.execution.steps[_].step.template.templateRef
	contains(lower(template_ref), "sast")
}

has_sast_step(stage) if {
	template_ref := stage.spec.execution.steps[_].stepGroup.template.templateRef
	contains(lower(template_ref), "sast")
}
