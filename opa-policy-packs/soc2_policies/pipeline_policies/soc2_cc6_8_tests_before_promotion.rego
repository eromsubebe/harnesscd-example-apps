# SOC 2 CC6.8 - Malicious Software Prevention
# Rule: Are pipelines required to pass automated tests before promoting to the next environment?
# Ensures every deployment stage is preceded by a stage containing automated test steps,
# preventing untested code from being promoted across environments.

package pipeline.soc2_cc6_8_tests_before_promotion

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Step types that qualify as automated tests
test_step_types := ["Run", "Test", "ShellScript", "Verify", "Plugin"]

# Stage types that can contain automated tests
test_stage_types := ["CI", "Build", "Custom"]

# --- POLICY RULES ---

# Deny deployment stages that have no preceding stage with automated tests
deny[msg] {
	some i
	input.pipeline.stages[i].stage.type == "Deployment"

	not has_preceding_test_stage(i)

	msg := sprintf(
		"SOC 2 CC6.8 Violation: Deployment stage '%s' has no preceding stage with automated tests. Pipelines must pass automated tests before promoting to the next environment.",
		[input.pipeline.stages[i].stage.name],
	)
}

# --- HELPER RULES ---

has_preceding_test_stage(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	stage.type in test_stage_types
	has_test_step(stage)
}

has_test_step(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in test_step_types
	contains(lower(step.name), "test")
}

has_test_step(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type == "Run"
	contains(lower(step.spec.command), "test")
}

has_test_step(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	contains(lower(step.spec.source.spec.script), "test")
}

has_test_step(stage) if {
	template_ref := stage.spec.execution.steps[_].step.template.templateRef
	contains(lower(template_ref), "test")
}

has_test_step(stage) if {
	template_ref := stage.spec.execution.steps[_].stepGroup.template.templateRef
	contains(lower(template_ref), "test")
}
