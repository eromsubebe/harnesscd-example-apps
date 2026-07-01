# PCI DSS v4.0 - Requirement 6.2.4 / 6.3.2
# "An inventory of bespoke and custom software, and third-party software components
#  incorporated into bespoke and custom software is maintained to facilitate
#  vulnerability and patch management."
#
# Ensures every CI/Build stage includes a Software Composition Analysis (SCA) step
# so that third-party dependencies are scanned for known vulnerabilities before
# artifacts are produced or deployed.

package pci_dss.req6_sca_required

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
sca_step_types := ["Security", "Snyk", "BlackDuck", "WhiteSource", "Mend", "Wiz"]

sca_template_patterns := [
	"account.SCA_Scan",
	"org.SCA_Scan",
	"account.Dependency_Scan",
	"org.Dependency_Scan",
]

build_stage_types := ["CI", "Build"]

# --- POLICY RULES ---

deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type in build_stage_types

	not has_sca_step(stage)
	not has_sca_template(stage)

	msg := sprintf(
		"PCI DSS 6.3.2 Violation: Build stage '%s' has no Software Composition Analysis (SCA) step. Third-party libraries and dependencies must be inventoried and scanned for known vulnerabilities before inclusion in deployable artifacts.",
		[stage.name],
	)
}

# --- HELPER RULES ---

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
}

has_sca_template(stage) if {
	template_ref := stage.spec.execution.steps[_].step.template.templateRef
	template_ref in sca_template_patterns
}
