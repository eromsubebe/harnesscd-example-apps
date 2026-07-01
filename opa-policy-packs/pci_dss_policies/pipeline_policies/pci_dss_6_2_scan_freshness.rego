# PCI DSS v4.0 - Requirement 6.3.1
# "Vulnerabilities are identified and managed — security vulnerabilities are
#  identified and addressed in a timely manner."
#
# Vulnerability scan results have a limited shelf life. New CVEs are disclosed daily,
# making stale scan results unreliable for risk assessment. This policy ensures that
# pipelines deploy only when fresh, inline security scans have been performed — not
# relying on cached or externally-provided scan data that may be outdated.

package pci_dss.req6_scan_freshness

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
vulnerability_scan_step_types := [
	"AquaTrivy", "Wiz", "Snyk", "Prisma", "Security",
	"Veracode", "BlackDuck", "WhiteSource", "Mend", "Checkmarx",
]

scan_stage_types := ["CI", "Build", "SecurityTests"]

# --- POLICY RULES ---

# Deny deployment stages that reference external scan results via variables
# without an inline scan in a preceding stage
deny[msg] {
	some i
	input.pipeline.stages[i].stage.type == "Deployment"

	has_scan_result_variable
	not has_inline_scan_before_deploy(i)

	msg := sprintf(
		"PCI DSS 6.3.1 Violation: Deployment stage '%s' references scan results via pipeline variables but has no inline scan in a preceding stage. Stale or externally-provided scan data may miss newly disclosed vulnerabilities — run a fresh scan within the pipeline.",
		[input.pipeline.stages[i].stage.name],
	)
}

# Deny deployment stages with no preceding inline scan at all
deny[msg] {
	some i
	input.pipeline.stages[i].stage.type == "Deployment"

	not has_inline_scan_before_deploy(i)

	msg := sprintf(
		"PCI DSS 6.3.1 Violation: Deployment stage '%s' has no inline vulnerability scan in a preceding stage. Timely vulnerability management requires fresh scans executed within the pipeline — external or cached results may not reflect the current threat landscape.",
		[input.pipeline.stages[i].stage.name],
	)
}

# --- HELPER RULES ---

has_scan_result_variable if {
	variable := input.pipeline.variables[_]
	contains(lower(variable.name), "scan")
}

has_scan_result_variable if {
	variable := input.pipeline.variables[_]
	contains(lower(variable.name), "vulnerability")
}

has_inline_scan_before_deploy(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	stage.type in scan_stage_types
	has_inline_scan_step(stage)
}

has_inline_scan_step(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in vulnerability_scan_step_types
}
