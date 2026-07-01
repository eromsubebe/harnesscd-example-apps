# PCI DSS v4.0 - Requirement 10.2.1 / 10.4.1
# "Audit logs capture all individual user access to cardholder data."
# "Audit logs are reviewed at least once daily to identify anomalies or suspicious
#  activity."
#
# Pipelines deploying to the CDE must have notification rules configured to alert
# security teams on failure, success, and rollback events. Without notifications,
# deployment activity to cardholder data systems goes unobserved — preventing timely
# detection of unauthorized changes or failed deployments that may indicate compromise.

package pci_dss.req10_notification_rules_required

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
cde_environments := ["production", "prod", "pci", "cde", "payment", "cardholder"]

required_notification_events := ["PipelineFailed", "PipelineSuccess", "StageRollback"]

# --- POLICY RULES ---

# Deny pipelines deploying to CDE without any notification rules
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_cde_environment(env_ref)

	not has_notification_rules

	msg := sprintf(
		"PCI DSS 10.2.1 Violation: Pipeline '%s' deploys to CDE environment '%s' but has no notification rules configured. Security teams must be alerted on all deployment activity (success, failure, and rollback) to cardholder data systems for timely review.",
		[input.pipeline.name, env_ref],
	)
}

# Deny pipelines deploying to CDE without a failure notification
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_cde_environment(env_ref)

	has_notification_rules
	not has_notification_for_event("PipelineFailed")

	msg := sprintf(
		"PCI DSS 10.4.1 Violation: Pipeline '%s' deploys to CDE environment '%s' but has no failure notification configured. Failed deployments to CDE must trigger immediate alerts to enable anomaly detection and incident response.",
		[input.pipeline.name, env_ref],
	)
}

# Deny pipelines deploying to CDE without a success notification
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_cde_environment(env_ref)

	has_notification_rules
	not has_notification_for_event("PipelineSuccess")

	msg := sprintf(
		"PCI DSS 10.4.1 Violation: Pipeline '%s' deploys to CDE environment '%s' but has no success notification configured. All successful deployments to CDE must be logged and communicated to security teams for audit trail completeness.",
		[input.pipeline.name, env_ref],
	)
}

# Deny pipelines deploying to CDE without a rollback/stage-failure notification
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_cde_environment(env_ref)

	has_notification_rules
	not has_notification_for_event("StageRollback")
	not has_notification_for_event("StageFailed")

	msg := sprintf(
		"PCI DSS 10.4.1 Violation: Pipeline '%s' deploys to CDE environment '%s' but has no rollback or stage-failure notification configured. Rollback events in the CDE indicate potential system instability and must alert security teams immediately.",
		[input.pipeline.name, env_ref],
	)
}

# --- HELPER RULES ---

is_cde_environment(env_ref) if {
	some env in cde_environments
	contains(lower(env_ref), env)
}

has_notification_rules if {
	input.pipeline.notificationRules
	count(input.pipeline.notificationRules) > 0
}

has_notification_for_event(event_type) if {
	rule := input.pipeline.notificationRules[_]
	event_type in rule.pipelineEvents
}

has_notification_for_event(event_type) if {
	rule := input.pipeline.notificationRules[_]
	some event in rule.pipelineEvents
	contains(event, event_type)
}
