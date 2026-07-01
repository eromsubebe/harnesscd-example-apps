# HIPAA Security Rule - 45 CFR § 164.312(e)(1) - Transmission Security
# Technical Safeguard: Implement technical security measures to guard against
# unauthorized access to electronic protected health information (ePHI) that is
# being transmitted over an electronic communications network.
#
# Rule: All connections transmitting or potentially transmitting PHI must use
# encryption in transit (HTTPS/TLS). Plain HTTP is prohibited.

package hipaa.encryption_in_transit

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Minimum TLS version required for HIPAA compliance
min_tls_version := "1.2"

# Environments that handle PHI and require strict TLS enforcement
phi_environments := ["production", "prod", "staging", "uat", "phi", "healthcare"]

# --- POLICY RULES ---

# Deny connectors configured with plain HTTP URLs
deny[msg] {
	connector := input.connector
	connector.spec.url
	startswith(connector.spec.url, "http://")

	msg := sprintf(
		"HIPAA 164.312(e)(1) Violation: Connector '%s' uses unencrypted HTTP ('%s'). All connections that may transmit ePHI must use HTTPS/TLS to protect data in transit.",
		[connector.name, connector.spec.url],
	)
}

# Deny Docker registry connectors configured with plain HTTP
deny[msg] {
	connector := input.connector
	connector.type == "DockerRegistry"
	connector.spec.dockerRegistryUrl
	startswith(connector.spec.dockerRegistryUrl, "http://")

	msg := sprintf(
		"HIPAA 164.312(e)(1) Violation: Docker registry connector '%s' uses unencrypted HTTP ('%s'). Healthcare artifact registries must use HTTPS/TLS.",
		[connector.name, connector.spec.dockerRegistryUrl],
	)
}

# Deny pipeline HTTP steps with plain HTTP URLs
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "Http"
	step.spec.url
	startswith(step.spec.url, "http://")

	msg := sprintf(
		"HIPAA 164.312(e)(1) Violation: HTTP step '%s' in stage '%s' uses unencrypted URL '%s'. All API calls that may transmit ePHI must use HTTPS/TLS.",
		[step.name, stage.name, step.spec.url],
	)
}

# Deny shell scripts that curl/wget to plain HTTP endpoints
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	step.spec.source.spec.script
	contains(step.spec.source.spec.script, "http://")

	msg := sprintf(
		"HIPAA 164.312(e)(1) Violation: Shell step '%s' in stage '%s' references a plain HTTP URL. All external connections in scripts that may transmit ePHI must use HTTPS/TLS.",
		[step.name, stage.name],
	)
}

# Deny deployments to PHI environments without TLS configuration
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_phi_environment(env_ref)

	not has_tls_enabled(stage)

	msg := sprintf(
		"HIPAA 164.312(e)(1) Violation: Deployment stage '%s' deploys to PHI environment '%s' without TLS configuration. All services handling ePHI must enforce encryption in transit.",
		[stage.name, env_ref],
	)
}

# Warn about TLS versions below 1.2
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.spec.tlsVersion
	step.spec.tlsVersion < min_tls_version

	msg := sprintf(
		"HIPAA 164.312(e)(1) Violation: Step '%s' in stage '%s' uses TLS version '%s' which is below the required minimum '%s'. Healthcare systems must use TLS 1.2 or higher.",
		[step.name, stage.name, step.spec.tlsVersion, min_tls_version],
	)
}

# --- HELPER RULES ---

is_phi_environment(env_ref) if {
	some phi_env in phi_environments
	contains(lower(env_ref), phi_env)
}

has_tls_enabled(stage) if {
	step := stage.spec.execution.steps[_].step
	step.spec.url
	startswith(step.spec.url, "https://")
}

has_tls_enabled(stage) if {
	manifest := stage.spec.manifests[_].manifest
	contains(lower(manifest.spec.store.spec.values), "tls")
	contains(lower(manifest.spec.store.spec.values), "enabled: true")
}
