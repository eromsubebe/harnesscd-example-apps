# HITRUST CSF v11 - 01.02 Event Logging and Monitoring
# Control Reference: 01.02.a, 01.02.b, 01.02.c
# Maps to: ISO/IEC 27001:2013 A.12.4.1, NIST CSF DE.CM-1, HIPAA 164.308(a)(1)(ii)(D)
#
# Requirement: Event logs recording user activities, exceptions, faults, and
# information security events are produced, kept, and regularly reviewed. Audit
# logs must be protected against tampering and unauthorized access.
#
# Rule: All pipelines handling PHI must have audit logging enabled to track
# activity, detect security incidents, and support forensic investigations.

package hitrust.audit_logging_and_monitoring

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Environments that handle PHI and require audit logging
phi_environments := ["production", "prod", "staging", "uat", "phi", "healthcare"]

# Events that must trigger audit notifications
audit_events := [
	"PipelineStart",
	"PipelineEnd",
	"PipelineSuccess",
	"PipelineFailed",
	"StageStart",
	"StageSuccess",
	"StageFailed",
	"ApprovalWaiting",
	"ApprovalApproved",
	"ApprovalRejected",
]

# Minimum audit retention period (in days)
min_retention_days := 2190  # 6 years for HIPAA compliance

# --- POLICY RULES ---

# Deny pipelines without notification rules for audit logging
deny[msg] {
	not has_notification_rules(input.pipeline)

	phi_related_pipeline := contains_phi_reference(input.pipeline)
	phi_related_pipeline

	msg := sprintf(
		"HITRUST 01.02.a Violation: Pipeline '%s' handles PHI but has no notification rules configured. Audit logging via notifications (Slack, email, webhook, SIEM) is required to track system activity and detect security incidents.",
		[input.pipeline.name],
	)
}

# Deny pipelines without comprehensive event coverage
deny[msg] {
	input.pipeline.notificationRules

	phi_related_pipeline := contains_phi_reference(input.pipeline)
	phi_related_pipeline

	not has_comprehensive_event_logging(input.pipeline)

	msg := sprintf(
		"HITRUST 01.02.a Violation: Pipeline '%s' has notification rules but does not log comprehensive audit events. Configure notifications for pipeline start/end, approvals, and failures to ensure complete audit trail for forensic investigations.",
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
		"HITRUST 01.02.b Violation: Deployment stage '%s' deploys to PHI environment '%s' without audit logging. All deployments handling PHI must have stage-level notifications enabled to track activity and satisfy audit requirements.",
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
		"HITRUST 01.02.b Violation: Approval step '%s' in stage '%s' in a PHI-handling pipeline has no audit logging. All approval activities must be logged with approver identity, timestamp, and decision to track access authorization decisions.",
		[step.name, stage.name],
	)
}

# Deny pipelines without audit trail metadata
deny[msg] {
	not input.pipeline.tags

	phi_related_pipeline := contains_phi_reference(input.pipeline)
	phi_related_pipeline

	msg := sprintf(
		"HITRUST 01.02.c Violation: Pipeline '%s' handles PHI but has no tags for audit classification. Add tags like 'phi-handling:true', 'audit-retention:%d', or 'compliance-scope:hitrust' to enable audit trail tracking and retention enforcement.",
		[input.pipeline.name, min_retention_days],
	)
}

# Warn about missing audit retention policy
deny[msg] {
	phi_related_pipeline := contains_phi_reference(input.pipeline)
	phi_related_pipeline

	not has_audit_retention_tag(input.pipeline)

	msg := sprintf(
		"HITRUST 01.02.c Warning: Pipeline '%s' handles PHI but has no 'audit-retention' tag. HITRUST/HIPAA requires audit logs to be retained for at least 6 years (%d days). Configure retention policy tags to ensure compliance.",
		[input.pipeline.name, min_retention_days],
	)
}

# Warn about pipelines without tamper-proof audit destinations
deny[msg] {
	input.pipeline.notificationRules

	phi_related_pipeline := contains_phi_reference(input.pipeline)
	phi_related_pipeline

	not has_tamper_proof_audit_destination(input.pipeline)

	msg := sprintf(
		"HITRUST 01.02.c Warning: Pipeline '%s' has audit logging but does not use tamper-proof destinations (SIEM, CloudWatch Logs, Stackdriver, Azure Monitor). Audit logs must be protected against modification and deletion to maintain evidentiary integrity.",
		[input.pipeline.name],
	)
}

# --- HELPER RULES ---

has_notification_rules(pipeline) if {
	pipeline.notificationRules
	count(pipeline.notificationRules) > 0
}

has_comprehensive_event_logging(pipeline) if {
	rule := pipeline.notificationRules[_]
	rule.pipelineEvents

	# Check if at least 3 key audit events are covered
	covered_events := [event | event := rule.pipelineEvents[_]; event in audit_events]
	count(covered_events) >= 3
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
	contains(lower(pipeline.name), "hitrust")
}

contains_phi_reference(pipeline) if {
	pipeline.tags
	pipeline.tags["phi-handling"] == "true"
}

contains_phi_reference(pipeline) if {
	pipeline.tags
	pipeline.tags["compliance-scope"] == "hitrust"
}

has_audit_retention_tag(pipeline) if {
	pipeline.tags
	pipeline.tags["audit-retention"]
}

has_tamper_proof_audit_destination(pipeline) if {
	rule := pipeline.notificationRules[_]
	rule.notificationMethod
	rule.notificationMethod.type in ["Webhook", "MicrosoftTeams", "PagerDuty"]
}

has_tamper_proof_audit_destination(pipeline) if {
	rule := pipeline.notificationRules[_]
	rule.notificationMethod.spec.webhookUrl
	webhook_url := rule.notificationMethod.spec.webhookUrl

	# Check for SIEM/log aggregation services
	contains(lower(webhook_url), "splunk")
}

has_tamper_proof_audit_destination(pipeline) if {
	rule := pipeline.notificationRules[_]
	rule.notificationMethod.spec.webhookUrl
	webhook_url := rule.notificationMethod.spec.webhookUrl

	contains(lower(webhook_url), "datadog")
}

has_tamper_proof_audit_destination(pipeline) if {
	rule := pipeline.notificationRules[_]
	rule.notificationMethod.spec.webhookUrl
	webhook_url := rule.notificationMethod.spec.webhookUrl

	contains(lower(webhook_url), "cloudwatch")
}
