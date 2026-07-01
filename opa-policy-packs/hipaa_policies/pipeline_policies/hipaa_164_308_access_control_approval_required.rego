# HIPAA Security Rule - 45 CFR § 164.308(a)(4) - Access Management
# Administrative Safeguard: Implement policies and procedures for authorizing access
# to electronic protected health information (ePHI) that are consistent with the
# applicable requirements of subpart E of this part.
#
# Rule: Deployments to PHI-handling environments must have explicit authorization
# via approval steps. Self-approval is prohibited.

package hipaa.access_control_approval_required

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Environments that handle PHI and require approval
phi_environments := ["production", "prod", "staging", "uat", "phi", "healthcare"]

# Approval step types that satisfy access authorization
approval_step_types := ["HarnessApproval", "JiraApproval", "ServiceNowApproval", "CustomApproval"]

# Minimum number of approvers required
min_approvers := 1

# --- POLICY RULES ---

# Deny deployment stages to PHI environments without preceding approval
deny[msg] {
	some i
	stage := input.pipeline.stages[i].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_phi_environment(env_ref)

	not has_preceding_approval(i)

	msg := sprintf(
		"HIPAA 164.308(a)(4) Violation: Deployment stage '%s' deploys to PHI environment '%s' without a preceding approval step. Access to ePHI systems must be explicitly authorized before deployment.",
		[stage.name, env_ref],
	)
}

# Deny approval steps that allow self-approval in PHI environments
deny[msg] {
	some i
	stage := input.pipeline.stages[i].stage
	step := stage.spec.execution.steps[_].step
	step.type == "HarnessApproval"

	# Check if this approval is before a PHI deployment
	deployment_index := get_next_deployment_index(i)
	deployment_stage := input.pipeline.stages[deployment_index].stage
	deployment_stage.type == "Deployment"

	env_ref := deployment_stage.spec.environment.environmentRef
	is_phi_environment(env_ref)

	# Check for self-approval setting
	step.spec.approvalCriteria
	step.spec.approvalCriteria.spec.includePipelineExecutionHistory == true

	msg := sprintf(
		"HIPAA 164.308(a)(4) Violation: Approval step '%s' in stage '%s' allows self-approval before deployment to PHI environment '%s'. Pipeline executors cannot authorize their own access to ePHI systems.",
		[step.name, stage.name, env_ref],
	)
}

# Deny approval steps with insufficient approver count
deny[msg] {
	some i
	stage := input.pipeline.stages[i].stage
	step := stage.spec.execution.steps[_].step
	step.type == "HarnessApproval"

	# Check if this approval is before a PHI deployment
	deployment_index := get_next_deployment_index(i)
	deployment_stage := input.pipeline.stages[deployment_index].stage
	deployment_stage.type == "Deployment"

	env_ref := deployment_stage.spec.environment.environmentRef
	is_phi_environment(env_ref)

	# Check approver count
	approver_count := count(step.spec.approvers.userGroups)
	approver_count < min_approvers

	msg := sprintf(
		"HIPAA 164.308(a)(4) Violation: Approval step '%s' in stage '%s' has %d approvers, but minimum %d required before deployment to PHI environment '%s'. Access authorization must be granted by designated security personnel.",
		[step.name, stage.name, approver_count, min_approvers, env_ref],
	)
}

# --- HELPER RULES ---

has_preceding_approval(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	step := stage.spec.execution.steps[_].step
	step.type in approval_step_types
}

get_next_deployment_index(current_index) := i if {
	some i
	i > current_index
	input.pipeline.stages[i].stage.type == "Deployment"
}

is_phi_environment(env_ref) if {
	some phi_env in phi_environments
	contains(lower(env_ref), phi_env)
}
