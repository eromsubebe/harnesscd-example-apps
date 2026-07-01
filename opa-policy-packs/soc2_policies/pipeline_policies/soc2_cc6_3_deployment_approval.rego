# SOC 2 CC6.3 - Logical and Physical Access Controls
# Requires authorized approval before deploying to sensitive environments.
# Ensures separation of duties and prevents unauthorized changes to production systems.

package soc2.cc6_3_deployment_approval

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Environments considered sensitive and requiring approval
sensitive_environments := ["production", "prod", "staging", "stg", "uat"]

# Valid approval step types
valid_approval_types := ["HarnessApproval", "JiraApproval", "ServiceNowApproval", "CustomApproval"]

# Minimum number of approvers required
min_approvers := 1

# --- POLICY RULES ---

# Deny deployments to sensitive environments without an approval step
deny[msg] {
	some i
	stage := input.pipeline.stages[i].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_sensitive_environment(env_ref)

	not stage_has_approval(stage)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Deployment stage '%s' targets sensitive environment '%s' without an approval step. Logical access controls require at least one authorized approver before deploying to sensitive environments.",
		[stage.name, env_ref],
	)
}

# Deny approval steps with fewer than the minimum required approvers
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_sensitive_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "HarnessApproval"
	step.spec.approvers.minimumCount < min_approvers

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Approval step '%s' in stage '%s' requires at least %d approver(s). Currently configured: %d.",
		[step.name, stage.name, min_approvers, step.spec.approvers.minimumCount],
	)
}

# --- HELPER RULES ---

is_sensitive_environment(env_ref) if {
	some env in sensitive_environments
	contains(lower(env_ref), env)
}

stage_has_approval(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in valid_approval_types
}

stage_has_approval(stage) if {
	template_ref := stage.spec.execution.steps[_].step.template.templateRef
	contains(lower(template_ref), "approval")
}
