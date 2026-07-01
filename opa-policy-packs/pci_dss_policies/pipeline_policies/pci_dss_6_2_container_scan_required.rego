# PCI DSS v4.0 - Requirement 6.2.4 / 6.3.1
# "Bespoke and custom software are developed securely — vulnerabilities in software
#  are identified and managed throughout the software development life cycle."
#
# Container images built by the pipeline must be scanned for vulnerabilities before
# being pushed to a registry or deployed. A pipeline that builds container images
# without scanning them allows unassessed artifacts into the CDE.

package pci_dss.req6_container_scan_required

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
build_push_step_types := [
	"BuildAndPushDockerRegistry",
	"BuildAndPushECR",
	"BuildAndPushACR",
	"BuildAndPushGCR",
]

container_scan_step_types := ["AquaTrivy", "Wiz", "Snyk", "Prisma", "Security"]

# --- POLICY RULES ---

# Deny build stages that produce container images without a container scan step
deny[msg] {
	stage := input.pipeline.stages[_].stage
	has_build_push_step(stage)

	not has_container_scan(stage)

	msg := sprintf(
		"PCI DSS 6.2.4 Violation: Stage '%s' builds container images but has no container vulnerability scan step. All container images must be scanned for known CVEs before being published or deployed to the CDE.",
		[stage.name],
	)
}

# Deny deployment stages without a preceding container scan when the pipeline builds images
deny[msg] {
	some i
	input.pipeline.stages[i].stage.type == "Deployment"

	has_build_stage_before(i)
	not has_container_scan_before(i)

	msg := sprintf(
		"PCI DSS 6.3.1 Violation: Deployment stage '%s' is preceded by a container build stage but no container image scan. Built images must be scanned for vulnerabilities before deployment to ensure known threats are addressed.",
		[input.pipeline.stages[i].stage.name],
	)
}

# --- HELPER RULES ---

has_build_push_step(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in build_push_step_types
}

has_container_scan(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in container_scan_step_types
}

has_container_scan(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "image")
	contains(lower(step.name), "scan")
}

has_container_scan(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "container")
	contains(lower(step.name), "scan")
}

has_build_stage_before(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	has_build_push_step(stage)
}

has_container_scan_before(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	has_container_scan(stage)
}
