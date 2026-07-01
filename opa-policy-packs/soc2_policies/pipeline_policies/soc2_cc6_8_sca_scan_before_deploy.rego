# SOC 2 CC6.8 - Malicious Software Prevention
# Rule: Does every pipeline run a dependency/SCA scan (open source vulnerabilities)?
# Requires every pipeline to run a Software Composition Analysis scan before any
# deployment stage to detect known vulnerabilities in third-party dependencies.

package pipeline.require_sca_scan_before_deploy

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Step types that qualify as SCA/dependency scans
sca_step_types := ["Security", "Snyk", "WhiteSource", "BlackDuck", "Mend", "Dependabot"]

# Stage types considered as containing SCA scans
scan_stage_types := ["CI", "Build", "SecurityTests"]

# --- POLICY RULES ---

# Deny deployment stages that have no preceding SCA/dependency scan
deny[msg] {
	some i
	input.pipeline.stages[i].stage.type == "Deployment"

	not has_preceding_sca_scan(i)

	msg := sprintf(
		"SOC 2 CC6.8 Violation: Deployment stage '%s' has no preceding dependency/SCA scan. Every pipeline must run a Software Composition Analysis scan before deploying to detect open source vulnerabilities.",
		[input.pipeline.stages[i].stage.name],
	)
}

# --- HELPER RULES ---

has_preceding_sca_scan(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	stage.type in scan_stage_types
	has_sca_step(stage)
}

has_sca_step(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in sca_step_types
}

has_sca_step(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "sca")
}

has_sca_step(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "dependency")
	contains(lower(step.name), "scan")
}

has_sca_step(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "composition")
	contains(lower(step.name), "analysis")
}

has_sca_step(stage) if {
	template_ref := stage.spec.execution.steps[_].step.template.templateRef
	contains(lower(template_ref), "sca")
}

has_sca_step(stage) if {
	template_ref := stage.spec.execution.steps[_].stepGroup.template.templateRef
	contains(lower(template_ref), "sca")
}

has_sca_step(stage) if {
	template_ref := stage.spec.execution.steps[_].step.template.templateRef
	contains(lower(template_ref), "dependency_scan")
}
