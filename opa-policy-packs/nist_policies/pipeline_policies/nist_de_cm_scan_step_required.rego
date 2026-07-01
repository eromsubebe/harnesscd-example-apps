# NIST CSF 2.0 - DE.CM (Continuous Monitoring)
# Maps to: DE.CM-01 — Networks and network services are monitored to find potentially
#   adverse events.
# Maps to: DE.CM-09 — Computing hardware and software, runtime environments, and their
#   data are monitored to find potentially adverse events.
#
# Guidance: Organizations must continuously monitor software components for known
# vulnerabilities. This policy ensures every deployment stage is preceded by a
# security scan step that evaluates container images and dependencies for CVEs.
# Without an inline scan step, the pipeline cannot guarantee that deployed artifacts
# have been assessed for known threats.

package nist.de_cm_scan_step_required

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Security scan step types that qualify as vulnerability assessment
vulnerability_scan_step_types := ["AquaTrivy", "Wiz", "Snyk", "Prisma", "Security", "Veracode", "BlackDuck", "WhiteSource", "Mend", "Checkmarx"]

# Stage types that can contain vulnerability scans
scan_stage_types := ["CI", "Build", "SecurityTests"]

# --- POLICY RULES ---

# Deny deployment stages without a preceding vulnerability scan stage
deny[msg] {
	some i
	input.pipeline.stages[i].stage.type == "Deployment"

	not has_preceding_scan_stage(i)

	msg := sprintf(
		"NIST CSF DE.CM-01 Violation: Deployment stage '%s' has no preceding security scan stage. Continuous monitoring requires that all container images and dependencies are scanned for known vulnerabilities before deployment.",
		[input.pipeline.stages[i].stage.name],
	)
}

# --- HELPER RULES ---

has_preceding_scan_stage(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	stage.type in scan_stage_types
	has_vulnerability_scan(stage)
}

has_vulnerability_scan(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in vulnerability_scan_step_types
}

has_vulnerability_scan(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "image")
	contains(lower(step.name), "scan")
}

has_vulnerability_scan(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "container")
	contains(lower(step.name), "scan")
}

has_vulnerability_scan(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "vulnerability")
}

has_vulnerability_scan(stage) if {
	template_ref := stage.spec.execution.steps[_].step.template.templateRef
	contains(lower(template_ref), "scan")
}
