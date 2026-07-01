# SOC 2 CC6.3 - Logical and Physical Access Controls
# Ensures pipelines are restricted from making outbound network calls to
# non-allowlisted destinations. All external connections must target approved endpoints.

package soc2.cc6_3_network_allowlist

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Allowlisted destination domains for outbound network calls
allowlisted_domains := [
	"your-org.jfrog.io",
	"us-docker.pkg.dev",
	"your-org.azurecr.io",
	"github.com",
	"api.github.com",
	"your-org.atlassian.net",
	"your-org.harness.io",
]

# Blocked destinations known to be risky or unauthorized
blocked_domains := [
	"pastebin.com",
	"requestbin.com",
	"ngrok.io",
	"webhook.site",
	"pipedream.net",
	"hookbin.com",
]

# --- POLICY RULES ---

# Deny HTTP steps calling non-allowlisted destinations
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "Http"
	step.spec.url

	not url_matches_allowlist(step.spec.url)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: HTTP step '%s' in stage '%s' makes an outbound call to '%s' which is not in the allowlisted destinations. All external network calls must target approved endpoints.",
		[step.name, stage.name, step.spec.url],
	)
}

# Deny shell steps that use curl/wget to blocked destinations
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	step.spec.source.spec.script

	some blocked in blocked_domains
	contains(lower(step.spec.source.spec.script), blocked)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Shell step '%s' in stage '%s' references blocked destination '%s'. Outbound network calls to unauthorized destinations are prohibited.",
		[step.name, stage.name, blocked],
	)
}

# Deny shell steps using curl with --upload-file or -T to non-allowlisted destinations
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	step.spec.source.spec.script

	script := step.spec.source.spec.script
	contains(script, "curl")
	has_upload_flag(script)
	not script_targets_allowlist(script)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Shell step '%s' in stage '%s' uploads data via curl to a destination not in the allowlist. Data exfiltration to unauthorized endpoints is prohibited.",
		[step.name, stage.name],
	)
}

# Deny webhook trigger URLs pointing to non-allowlisted destinations
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "Plugin"
	step.spec.settings.webhook_url

	not url_matches_allowlist(step.spec.settings.webhook_url)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Plugin step '%s' in stage '%s' sends a webhook to '%s' which is not in the allowlisted destinations.",
		[step.name, stage.name, step.spec.settings.webhook_url],
	)
}

# --- HELPER RULES ---

url_matches_allowlist(url) if {
	some domain in allowlisted_domains
	contains(lower(url), lower(domain))
}

script_targets_allowlist(script) if {
	some domain in allowlisted_domains
	contains(lower(script), lower(domain))
}

has_upload_flag(script) if {
	contains(script, "--upload-file")
}

has_upload_flag(script) if {
	contains(script, " -T ")
}
