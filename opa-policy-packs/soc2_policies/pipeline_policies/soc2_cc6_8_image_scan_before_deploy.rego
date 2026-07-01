# SOC 2 CC6.8 - Malicious Software Prevention
# Rule: Does every pipeline run a container image scan before deploying?
# Requires every pipeline to run a container image scan before any deployment stage.
# Ensures vulnerabilities and malicious software in container images are identified
# prior to production release.

package pipeline.require_image_scan_before_deploy

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Step types that qualify as container image scans
image_scan_step_types := ["AquaTrivy", "Wiz", "Snyk", "Prisma", "Security"]

# Stage types considered as containing image scans
scan_stage_types := ["CI", "Build", "SecurityTests"]

# --- POLICY RULES ---

# Deny deployment stages that have no preceding container image scan stage
deny[msg] {
	some i
	input.pipeline.stages[i].stage.type == "Deployment"

	not has_preceding_image_scan(i)

	msg := sprintf(
		"Policy Violation: Deployment stage '%s' has no preceding container image scan. Every pipeline must run an image scan before deploying to ensure container vulnerabilities are identified.",
		[input.pipeline.stages[i].stage.name],
	)
}

# --- HELPER RULES ---

has_preceding_image_scan(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	stage.type in scan_stage_types
	has_image_scan_step(stage)
}

has_image_scan_step(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in image_scan_step_types
}

has_image_scan_step(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "image")
	contains(lower(step.name), "scan")
}

has_image_scan_step(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "container")
	contains(lower(step.name), "scan")
}

has_image_scan_step(stage) if {
	template_ref := stage.spec.execution.steps[_].step.template.templateRef
	contains(lower(template_ref), "container_image_scan")
}

has_image_scan_step(stage) if {
	template_ref := stage.spec.execution.steps[_].stepGroup.template.templateRef
	contains(lower(template_ref), "container_image_scan")
}
