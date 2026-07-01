# NIST CSF 2.0 - PR.AA (Identity Management, Authentication, and Access Control)
# Rule: The person who writes and commits the code cannot also be the one who approves
# it for production. Build, review, and deploy must be owned by distinct identities.
# Enforces separation of duties by requiring that pipeline executors cannot self-approve
# and that approval steps mandate multiple distinct approvers.

package nist.pr_aa_separation_of_duties

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Environments requiring separation of duties
protected_environments := ["production", "prod", "staging", "stg", "uat"]

# Approval step types that must enforce separation of duties
approval_step_types := ["HarnessApproval", "JiraApproval", "ServiceNowApproval", "CustomApproval"]

# Minimum number of approvers to ensure distinct identities in the review/approve process
min_approvers := 2

# --- POLICY RULES ---

# Deny HarnessApproval steps that allow self-approval
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "HarnessApproval"
	step.spec.approvers.disallowPipelineExecutor != true

	msg := sprintf(
		"NIST CSF PR.AA Violation: Approval step '%s' in stage '%s' (environment '%s') allows the pipeline executor to approve their own deployment. Separation of duties requires that build, review, and deploy are owned by distinct identities.",
		[step.name, stage.name, env_ref],
	)
}

# Deny JiraApproval steps that allow self-approval
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "JiraApproval"
	step.spec.approvers.disallowPipelineExecutor != true

	msg := sprintf(
		"NIST CSF PR.AA Violation: JiraApproval step '%s' in stage '%s' (environment '%s') allows the pipeline executor to approve their own deployment. Separation of duties requires that build, review, and deploy are owned by distinct identities.",
		[step.name, stage.name, env_ref],
	)
}

# Deny ServiceNowApproval steps that allow self-approval
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "ServiceNowApproval"
	step.spec.approvers.disallowPipelineExecutor != true

	msg := sprintf(
		"NIST CSF PR.AA Violation: ServiceNowApproval step '%s' in stage '%s' (environment '%s') allows the pipeline executor to approve their own deployment. Separation of duties requires that build, review, and deploy are owned by distinct identities.",
		[step.name, stage.name, env_ref],
	)
}

# Deny CustomApproval steps that allow self-approval
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "CustomApproval"
	step.spec.approvers.disallowPipelineExecutor != true

	msg := sprintf(
		"NIST CSF PR.AA Violation: CustomApproval step '%s' in stage '%s' (environment '%s') allows the pipeline executor to approve their own deployment. Separation of duties requires that build, review, and deploy are owned by distinct identities.",
		[step.name, stage.name, env_ref],
	)
}

# Deny approval steps with fewer than the minimum required approvers
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "HarnessApproval"
	step.spec.approvers.minimumCount < min_approvers

	msg := sprintf(
		"NIST CSF PR.AA Violation: Approval step '%s' in stage '%s' requires only %d approver(s). Separation of duties requires at least %d distinct approvers to ensure independent review before production deployment.",
		[step.name, stage.name, step.spec.approvers.minimumCount, min_approvers],
	)
}

# Deny deployment stages to protected environments without any approval step
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	not stage_has_approval(stage)

	msg := sprintf(
		"NIST CSF PR.AA Violation: Deployment stage '%s' targets protected environment '%s' with no approval step. Separation of duties requires an independent review gate between code commit and production deployment.",
		[stage.name, env_ref],
	)
}

# --- HELPER RULES ---

is_protected_environment(env_ref) if {
	some env in protected_environments
	contains(lower(env_ref), env)
}

stage_has_approval(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in approval_step_types
}
