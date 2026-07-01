# HITRUST CSF v11 - 09.01 Change Control
# Control Reference: 09.01.a, 09.01.b, 09.01.c
# Maps to: ISO/IEC 27001:2013 A.12.1.2, NIST CSF PR.IP-3
#
# Requirement: The organization formally controls changes to information processing
# facilities and systems. Changes to production systems handling PHI must be tracked,
# approved, and reversible.
#
# Rule: All deployment stages must have change tracking via version control, approval
# workflows, and rollback mechanisms.

package hitrust.change_control_required

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Environments requiring change control
protected_environments := ["production", "prod", "staging", "uat", "phi", "healthcare"]

# Approval step types that satisfy change authorization
approval_step_types := ["HarnessApproval", "JiraApproval", "ServiceNowApproval", "CustomApproval"]

# --- POLICY RULES ---

# Deny deployment stages to protected environments without version control
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	not has_version_control(stage)

	msg := sprintf(
		"HITRUST 09.01.a Violation: Deployment stage '%s' deploys to protected environment '%s' without version control tracking. All changes to production systems handling PHI must be tracked via Git commit SHA, image tags, or artifact versions.",
		[stage.name, env_ref],
	)
}

# Deny deployment stages to protected environments without preceding approval
deny[msg] {
	some i
	stage := input.pipeline.stages[i].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	not has_preceding_approval(i)

	msg := sprintf(
		"HITRUST 09.01.b Violation: Deployment stage '%s' deploys to protected environment '%s' without a preceding approval step. All changes to production PHI systems must be formally authorized before implementation.",
		[stage.name, env_ref],
	)
}

# Deny deployment stages without rollback capability
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	not has_rollback_mechanism(stage)

	msg := sprintf(
		"HITRUST 09.01.c Violation: Deployment stage '%s' deploys to protected environment '%s' without a rollback mechanism. All production changes must be reversible to ensure business continuity if issues are detected.",
		[stage.name, env_ref],
	)
}

# Deny pipelines without change tracking metadata
deny[msg] {
	not input.pipeline.tags

	has_protected_deployment := deployment_to_protected_env

	msg := sprintf(
		"HITRUST 09.01.a Violation: Pipeline '%s' deploys to protected environments but has no tags for change tracking. Add tags like 'change-ticket', 'release-version', or 'jira-ticket' to link deployments to change requests.",
		[input.pipeline.name],
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

has_version_control(stage) if {
	stage.spec.serviceConfig
	stage.spec.serviceConfig.serviceDefinition.spec.artifacts
}

has_version_control(stage) if {
	stage.spec.manifests
	manifest := stage.spec.manifests[_].manifest
	manifest.spec.store.spec.gitFetchType == "Branch"
	manifest.spec.store.spec.branch
}

has_version_control(stage) if {
	stage.spec.manifests
	manifest := stage.spec.manifests[_].manifest
	manifest.spec.store.spec.commitId
}

has_rollback_mechanism(stage) if {
	stage.failureStrategies
	failure_strategy := stage.failureStrategies[_]
	failure_strategy.spec.action == "StageRollback"
}

has_rollback_mechanism(stage) if {
	stage.spec.execution.rollbackSteps
	count(stage.spec.execution.rollbackSteps) > 0
}

is_protected_environment(env_ref) if {
	some protected in protected_environments
	contains(lower(env_ref), protected)
}

deployment_to_protected_env if {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"
	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)
}
