# HITRUST CSF v11 - 01.01 Separation of Duties
# Control Reference: 01.01.a, 01.01.b
# Maps to: ISO/IEC 27001:2013 A.6.1.2, SOC 2 CC6.3, HIPAA 164.308(a)(3)(i)
#
# Requirement: Duties and areas of responsibility are segregated to reduce
# opportunities for unauthorized or unintentional modification or misuse of
# organizational assets.
#
# Rule: The person who writes and commits code cannot be the same person who
# approves deployment to production PHI environments. Multi-party authorization
# is required.

package hitrust.separation_of_duties

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Environments requiring separation of duties
protected_environments := ["production", "prod", "staging", "uat", "phi", "healthcare"]

# Approval step types
approval_step_types := ["HarnessApproval", "JiraApproval", "ServiceNowApproval", "CustomApproval"]

# Minimum number of distinct approvers
min_approvers := 2

# --- POLICY RULES ---

# Deny HarnessApproval steps that allow self-approval in protected environments
deny[msg] {
	some i
	stage := input.pipeline.stages[i].stage
	step := stage.spec.execution.steps[_].step
	step.type == "HarnessApproval"

	# Check if this approval is before a protected deployment
	deployment_index := get_next_deployment_index(i)
	deployment_stage := input.pipeline.stages[deployment_index].stage
	deployment_stage.type == "Deployment"

	env_ref := deployment_stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	# Check for self-approval setting
	step.spec.approvalCriteria
	step.spec.approvalCriteria.spec.includePipelineExecutionHistory == true

	msg := sprintf(
		"HITRUST 01.01.a Violation: Approval step '%s' in stage '%s' allows self-approval before deployment to protected environment '%s'. Pipeline executors cannot approve their own changes to PHI systems — separation of duties is required.",
		[step.name, stage.name, env_ref],
	)
}

# Deny approval steps with insufficient distinct approvers
deny[msg] {
	some i
	stage := input.pipeline.stages[i].stage
	step := stage.spec.execution.steps[_].step
	step.type == "HarnessApproval"

	# Check if this approval is before a protected deployment
	deployment_index := get_next_deployment_index(i)
	deployment_stage := input.pipeline.stages[deployment_index].stage
	deployment_stage.type == "Deployment"

	env_ref := deployment_stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	# Count approvers
	approver_count := count(step.spec.approvers.userGroups)
	approver_count < min_approvers

	msg := sprintf(
		"HITRUST 01.01.b Violation: Approval step '%s' in stage '%s' has %d approver(s), but minimum %d distinct approvers required before deployment to protected environment '%s'. Multi-party authorization ensures proper segregation of duties.",
		[step.name, stage.name, approver_count, min_approvers, env_ref],
	)
}

# Deny pipelines without approval workflows for protected deployments
deny[msg] {
	some i
	stage := input.pipeline.stages[i].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	not has_preceding_approval(i)

	msg := sprintf(
		"HITRUST 01.01.a Violation: Deployment stage '%s' deploys to protected environment '%s' without a preceding approval step. Separation of duties requires that deployment authorization be granted by personnel independent of code authorship.",
		[stage.name, env_ref],
	)
}

# Deny approval steps that use the same user group for both approval and execution
deny[msg] {
	some i
	stage := input.pipeline.stages[i].stage
	step := stage.spec.execution.steps[_].step
	step.type == "HarnessApproval"

	# Check if this approval is before a protected deployment
	deployment_index := get_next_deployment_index(i)
	deployment_stage := input.pipeline.stages[deployment_index].stage
	deployment_stage.type == "Deployment"

	env_ref := deployment_stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	# Check if same user group is used for approval and pipeline execution
	approver_group := step.spec.approvers.userGroups[_]
	contains(lower(approver_group), "developers")

	msg := sprintf(
		"HITRUST 01.01.a Violation: Approval step '%s' in stage '%s' uses user group '%s' which likely includes code authors. Approvers for protected environment '%s' must be organizationally separate from developers (e.g., security, operations, compliance teams).",
		[step.name, stage.name, approver_group, env_ref],
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

is_protected_environment(env_ref) if {
	some protected in protected_environments
	contains(lower(env_ref), protected)
}
