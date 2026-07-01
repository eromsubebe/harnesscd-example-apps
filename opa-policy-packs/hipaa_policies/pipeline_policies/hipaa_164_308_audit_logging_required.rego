# HIPAA Security Rule - 45 CFR § 164.308(a)(1)(ii)(D) - Information System Activity Review
# Administrative Safeguard: Implement procedures to regularly review records of
# information system activity, such as audit logs, access reports, and security
# incident tracking reports.
#
# Rule: All pipelines handling PHI must have audit logging enabled to track
# activity and detect potential security incidents.

package hipaa.audit_logging_required

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Environments that handle PHI and require audit logging
phi_environments := ["production", "prod", "staging", "uat", "phi", "healthcare"]

# Pipeline stages that must have audit logging
auditable_stage_types := ["Deployment", "Approval", "Custom"]

# --- POLICY RULES ---

# Deny pipelines without notification rules for audit logging
deny[msg] {
	not has_notification_rules(input.pipeline)

	phi_related_pipeline := contains_phi_reference(input.pipeline)
	phi_related_pipeline

	msg := sprintf(
		"HIPAA 164.308(a)(1)(ii)(D) Violation: Pipeline '%s' handles PHI but has no notification rules configured. Audit logging via notifications (Slack, email, webhook) is required to track system activity and detect security incidents.",
		[input.pipeline.name],
	)
}

# Deny deployment stages to PHI environments without audit logging
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_phi_environment(env_ref)

	not has_stage_notification(stage)

	msg := sprintf(
		"HIPAA 164.308(a)(1)(ii)(D) Violation: Deployment stage '%s' deploys to PHI environment '%s' without audit logging. All deployments handling ePHI must have notifications enabled to track activity.",
		[stage.name, env_ref],
	)
}

# Deny approval stages without audit logging
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in ["HarnessApproval", "JiraApproval", "ServiceNowApproval"]

	phi_related_pipeline := contains_phi_reference(input.pipeline)
	phi_related_pipeline

	not has_stage_notification(stage)

	msg := sprintf(
		"HIPAA 164.308(a)(1)(ii)(D) Violation: Approval step '%s' in stage '%s' in a PHI-handling pipeline has no audit logging. All approval activities must be logged to track access decisions.",
		[step.name, stage.name],
	)
}

# Deny pipelines without audit trail metadata
deny[msg] {
	not input.pipeline.tags
	phi_related_pipeline := contains_phi_reference(input.pipeline)
	phi_related_pipeline

	msg := sprintf(
		"HIPAA 164.308(a)(1)(ii)(D) Violation: Pipeline '%s' handles PHI but has no tags for audit classification. Add tags like 'phi-handling:true' or 'hipaa-scope:yes' to enable audit trail tracking.",
		[input.pipeline.name],
	)
}

# Warn about missing audit retention policy
deny[msg] {
	phi_related_pipeline := contains_phi_reference(input.pipeline)
	phi_related_pipeline

	not has_audit_retention_tag(input.pipeline)

	msg := sprintf(
		"HIPAA 164.308(a)(1)(ii)(D) Warning: Pipeline '%s' handles PHI but has no 'audit-retention' tag. HIPAA requires audit logs to be retained for at least 6 years. Configure retention policy tags to ensure compliance.",
		[input.pipeline.name],
	)
}

# --- HELPER RULES ---

has_notification_rules(pipeline) if {
	pipeline.notificationRules
	count(pipeline.notificationRules) > 0
}

has_stage_notification(stage) if {
	stage.spec.notifications
	count(stage.spec.notifications) > 0
}

is_phi_environment(env_ref) if {
	some phi_env in phi_environments
	contains(lower(env_ref), phi_env)
}

contains_phi_reference(pipeline) if {
	contains(lower(pipeline.name), "phi")
}

contains_phi_reference(pipeline) if {
	contains(lower(pipeline.name), "healthcare")
}

contains_phi_reference(pipeline) if {
	contains(lower(pipeline.name), "hipaa")
}

contains_phi_reference(pipeline) if {
	pipeline.tags
	pipeline.tags["phi-handling"] == "true"
}

contains_phi_reference(pipeline) if {
	pipeline.tags
	pipeline.tags["hipaa-scope"] == "yes"
}

has_audit_retention_tag(pipeline) if {
	pipeline.tags
	pipeline.tags["audit-retention"]
}
