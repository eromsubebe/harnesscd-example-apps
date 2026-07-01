# NIST CSF 2.0 - DE.CM (Continuous Monitoring)
# Maps to: DE.CM-09 — Computing hardware and software, runtime environments, and their
#   data are monitored to find potentially adverse events.
# Maps to: ID.RA-01 — Vulnerabilities in assets are identified, validated, and recorded.
# Maps to: PR.PS-02 — Software is maintained, replaced, and removed commensurate
#   with risk.
#
# Guidance: Vulnerability scan results have a limited shelf life. New CVEs are disclosed
# daily, making stale scan results unreliable for risk assessment. This policy ensures
# that pipelines run inline security scans (not relying on cached/external results)
# and that any referenced scan timestamps are validated against a freshness TTL.
# Scan results older than the defined TTL must be treated as non-compliant.

package nist.de_cm_scan_freshness

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Security scan step types that must run inline (not reference stale results)
vulnerability_scan_step_types := ["AquaTrivy", "Wiz", "Snyk", "Prisma", "Security", "Veracode", "BlackDuck", "WhiteSource", "Mend", "Checkmarx"]

# Stage types that can contain inline scans
scan_stage_types := ["CI", "Build", "SecurityTests"]

# --- POLICY RULES ---

# Deny deployment stages that rely on external scan results passed as variables
# without a freshness validation step
deny[msg] {
	some i
	input.pipeline.stages[i].stage.type == "Deployment"

	has_scan_result_variable
	not has_inline_scan_before_deploy(i)
	not has_scan_freshness_check(i)

	msg := sprintf(
		"NIST CSF DE.CM-09 Violation: Deployment stage '%s' references external scan results via pipeline variables but has no inline scan or freshness validation step. Stale scan results (beyond TTL) must be treated as non-compliant — run an inline scan or validate scan timestamp before deployment.",
		[input.pipeline.stages[i].stage.name],
	)
}

# Deny pipelines that have no inline scan step at all before deployment
# (relying entirely on external/cached scan data)
deny[msg] {
	some i
	input.pipeline.stages[i].stage.type == "Deployment"

	not has_inline_scan_before_deploy(i)

	msg := sprintf(
		"NIST CSF DE.CM-09 Violation: Deployment stage '%s' has no inline vulnerability scan in a preceding stage. Continuous monitoring requires fresh scan execution within the pipeline — external or cached scan results may exceed the acceptable TTL and miss newly disclosed vulnerabilities.",
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

has_scan_freshness_check(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "freshness")
}

has_scan_freshness_check(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "ttl")
	contains(lower(step.name), "valid")
}
