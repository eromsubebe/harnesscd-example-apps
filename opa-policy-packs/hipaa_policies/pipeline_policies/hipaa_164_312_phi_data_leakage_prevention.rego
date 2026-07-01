# HIPAA Security Rule - 45 CFR § 164.312(a)(1) - Access Control
# Technical Safeguard: Implement technical policies and procedures for electronic
# information systems that maintain electronic protected health information (ePHI)
# to allow access only to those persons or software programs that have been granted
# access rights.
#
# Rule: Prevent data leakage by blocking pipelines from exposing PHI to unauthorized
# external endpoints, public logs, or untrusted third-party services.

package hipaa.phi_data_leakage_prevention

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Blocked external destinations that should not receive PHI
blocked_external_destinations := [
	"pastebin.com",
	"requestbin.com",
	"ngrok.io",
	"webhook.site",
	"pipedream.net",
	"hookbin.com",
	"postman-echo.com",
]

# Allowlisted approved destinations for PHI (e.g., HIPAA-compliant data warehouses)
approved_phi_destinations := [
	"your-org.snowflakecomputing.com",
	"your-org-hipaa.databricks.com",
	"your-org-phi.vault.azure.net",
]

# Log aggregation services that must not receive raw PHI
public_log_services := [
	"logs.datadoghq.com",
	"logs.splunk.com",
	"logs.newrelic.com",
]

# --- POLICY RULES ---

# Deny HTTP steps calling blocked external destinations
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "Http"
	step.spec.url

	some blocked in blocked_external_destinations
	contains(lower(step.spec.url), blocked)

	msg := sprintf(
		"HIPAA 164.312(a)(1) Violation: HTTP step '%s' in stage '%s' calls blocked external destination '%s'. PHI must not be transmitted to untrusted third-party endpoints. Use approved HIPAA-compliant services only.",
		[step.name, stage.name, blocked],
	)
}

# Deny shell scripts that curl/wget to blocked external destinations
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	step.spec.source.spec.script

	some blocked in blocked_external_destinations
	contains(lower(step.spec.source.spec.script), blocked)

	msg := sprintf(
		"HIPAA 164.312(a)(1) Violation: Shell script step '%s' in stage '%s' references blocked external destination '%s'. PHI must not be exfiltrated to untrusted endpoints via scripts.",
		[step.name, stage.name, blocked],
	)
}

# Deny steps that upload to public log aggregation services without redaction
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.spec.url

	some log_service in public_log_services
	contains(lower(step.spec.url), log_service)

	not has_phi_redaction_enabled(step)

	msg := sprintf(
		"HIPAA 164.312(a)(1) Violation: Step '%s' in stage '%s' uploads logs to '%s' without PHI redaction. Raw PHI must not be transmitted to public log aggregation services. Enable PHI redaction or use HIPAA-compliant logging infrastructure.",
		[step.name, stage.name, log_service],
	)
}

# Deny pipelines that export PHI to unapproved destinations
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.spec.url

	not url_in_approved_destinations(step.spec.url)
	not url_in_blocked_destinations(step.spec.url)

	contains(lower(step.name), "phi")
	contains(lower(step.name), "export")

	msg := sprintf(
		"HIPAA 164.312(a)(1) Violation: Step '%s' in stage '%s' exports PHI to unapproved destination '%s'. PHI must only be transmitted to HIPAA-compliant approved endpoints.",
		[step.name, stage.name, step.spec.url],
	)
}

# --- HELPER RULES ---

has_phi_redaction_enabled(step) if {
	step.spec.envVariables
	step.spec.envVariables.PHI_REDACTION_ENABLED == "true"
}

has_phi_redaction_enabled(step) if {
	contains(lower(step.spec.source.spec.script), "redact_phi")
}

url_in_approved_destinations(url) if {
	some approved in approved_phi_destinations
	contains(lower(url), lower(approved))
}

url_in_blocked_destinations(url) if {
	some blocked in blocked_external_destinations
	contains(lower(url), blocked)
}
