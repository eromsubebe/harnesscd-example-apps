# PCI DSS v4.0 - Requirement 6.5.1 / 6.5.2 / 6.5.4
# "Changes to all software components on production systems are made according to
#  established processes that include:
#  - Documentation of impact
#  - Documented change approval by authorized parties
#  - Testing that verifies the change does not adversely impact system security
#  - Procedures to address failures and return to a secure state"
#
# Ensures deployment pipelines targeting CDE/production environments have proper
# change control: approval gates, pre-deployment testing, and rollback capability.

package pci_dss.req6_change_control

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
cde_environments := ["production", "prod", "pci", "cde", "payment", "cardholder"]

approval_step_types := ["HarnessApproval", "JiraApproval", "ServiceNowApproval", "CustomApproval"]

change_ticket_step_types := ["JiraCreate", "ServiceNowCreate", "JiraApproval", "ServiceNowApproval"]

min_approvers := 2

test_stage_types := ["CI", "Build", "SecurityTests"]

# --- POLICY RULES ---

# 6.5.2: Deny deployments to CDE without an approval gate
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_cde_environment(env_ref)

	not stage_has_approval(stage)

	msg := sprintf(
		"PCI DSS 6.5.2 Violation: Deployment stage '%s' targets CDE environment '%s' without an approval step. All changes to production/CDE systems require documented approval by authorized parties before deployment.",
		[stage.name, env_ref],
	)
}

# 6.5.2: Deny approval steps that allow self-approval
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_cde_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "HarnessApproval"
	step.spec.approvers.disallowPipelineExecutor != true

	msg := sprintf(
		"PCI DSS 6.5.2 Violation: Approval step '%s' in stage '%s' allows the pipeline executor to approve their own change. Change approval must come from a party other than the individual who made the change.",
		[step.name, stage.name],
	)
}

# 6.5.2: Deny approval steps with fewer than minimum approvers
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_cde_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "HarnessApproval"
	step.spec.approvers.minimumCount < min_approvers

	msg := sprintf(
		"PCI DSS 6.5.2 Violation: Approval step '%s' in stage '%s' requires only %d approver(s). CDE deployments require at least %d independent approvers to validate the change.",
		[step.name, stage.name, step.spec.approvers.minimumCount, min_approvers],
	)
}

# 6.5.1: Deny CDE deployments without a change management ticket
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_cde_environment(env_ref)

	not has_change_ticket(stage)

	msg := sprintf(
		"PCI DSS 6.5.1 Violation: Deployment stage '%s' to CDE environment '%s' has no change management ticket step. All changes to CDE systems must be documented with impact analysis in a tracked change request.",
		[stage.name, env_ref],
	)
}

# 6.5.4: Deny CDE deployments without preceding test stages
deny[msg] {
	some i
	stage := input.pipeline.stages[i].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_cde_environment(env_ref)

	not has_preceding_test_stage(i)

	msg := sprintf(
		"PCI DSS 6.5.4 Violation: Deployment stage '%s' to CDE environment '%s' has no preceding test stage. Changes must be tested to verify they do not adversely impact system security before production deployment.",
		[stage.name, env_ref],
	)
}

# 6.5.4: Deny CDE deployments without rollback steps
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_cde_environment(env_ref)

	not has_rollback(stage)

	msg := sprintf(
		"PCI DSS 6.5.4 Violation: Deployment stage '%s' to CDE environment '%s' has no rollback steps configured. Procedures to address failures and return to a secure state are required for all CDE changes.",
		[stage.name, env_ref],
	)
}

# --- HELPER RULES ---

is_cde_environment(env_ref) if {
	some env in cde_environments
	contains(lower(env_ref), env)
}

stage_has_approval(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in approval_step_types
}

has_change_ticket(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in change_ticket_step_types
}

has_preceding_test_stage(deploy_index) if {
	some j
	j < deploy_index
	stage := input.pipeline.stages[j].stage
	stage.type in test_stage_types
}

has_rollback(stage) if {
	stage.spec.execution.rollbackSteps
	count(stage.spec.execution.rollbackSteps) > 0
}

has_rollback(stage) if {
	step := stage.spec.execution.steps[_].step
	step.type in ["K8sRollingRollback", "K8sBGSwapServices", "K8sCanaryDelete", "HelmRollback", "TerraformRollback"]
}
