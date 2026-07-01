# SOC 2 CC8 - Change Management
# Rule: Does every production deployment have a documented rollback mechanism?
# Ensures all deployment stages targeting production environments have rollback
# steps configured to enable rapid recovery from failed deployments.

package pipeline.soc2_cc8_rollback_mechanism

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Environments that require a rollback mechanism
production_environments := ["production", "prod"]

# Step types that qualify as rollback mechanisms
rollback_step_types := [
	"K8sRollingRollback",
	"K8sBGSwapServices",
	"K8sCanaryDelete",
	"TerraformRollback",
	"HelmRollback",
]

# --- POLICY RULES ---

# Deny production deployment stages without rollback steps
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_production_environment(env_ref)

	not has_rollback_mechanism(stage)

	msg := sprintf(
		"SOC 2 CC8 Violation: Deployment stage '%s' targets production environment '%s' but has no rollback mechanism configured. Every production deployment must have a documented rollback to enable rapid recovery from failed changes.",
		[stage.name, env_ref],
	)
}

# --- HELPER RULES ---

is_production_environment(env_ref) if {
	some env in production_environments
	contains(lower(env_ref), env)
}

has_rollback_mechanism(stage) if {
	stage.spec.execution.rollbackSteps
	count(stage.spec.execution.rollbackSteps) > 0
}

has_rollback_mechanism(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in rollback_step_types
}

has_rollback_mechanism(stage) if {
	step := stage.spec.execution.steps[_].step
	contains(lower(step.name), "rollback")
}
