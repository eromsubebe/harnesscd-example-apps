# PCI DSS v4.0 - Requirement 6.2.4
# "Software engineering techniques or other methods are defined and in use by
#  software development personnel to prevent or mitigate common software attacks
#  and related vulnerabilities in bespoke and custom software."
#
# Ensures every CI/Build stage includes a Static Application Security Testing (SAST)
# step so that code-level vulnerabilities are detected before artifacts are produced.

package pci_dss.req6_sast_required

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
sast_step_types := ["Security", "Veracode", "SonarQube", "Checkmarx", "Fortify", "Snyk"]

sast_template_patterns := [
	"account.SAST_Scan",
	"org.SAST_Scan",
	"account.Static_Analysis",
	"org.Static_Analysis",
]

build_stage_types := ["CI", "Build"]

# --- POLICY RULES ---

deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type in build_stage_types

	not has_sast_step(stage)
	not has_sast_template(stage)

	msg := sprintf(
		"PCI DSS 6.2.4 Violation: Build stage '%s' has no Static Application Security Testing (SAST) step. All custom code must undergo static analysis to detect common vulnerabilities (injection, XSS, buffer overflow) before build artifacts are produced.",
		[stage.name],
	)
}

# --- HELPER RULES ---

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

has_sast_template(stage) if {
	template_ref := stage.spec.execution.steps[_].step.template.templateRef
	template_ref in sast_template_patterns
}
