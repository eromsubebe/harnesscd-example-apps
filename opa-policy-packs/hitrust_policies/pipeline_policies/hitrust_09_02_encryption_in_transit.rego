# HITRUST CSF v11 - 09.02 Encryption and Key Management
# Control Reference: 09.02.a, 09.02.b
# Maps to: ISO/IEC 27001:2013 A.10.1.1, NIST CSF PR.DS-2, HIPAA 164.312(e)(1)
#
# Requirement: A policy on the use of cryptographic controls for protection of
# information is developed and implemented. Information in transit is protected
# via encryption.
#
# Rule: All connections that may transmit PHI must use encryption in transit
# (HTTPS/TLS 1.2+). Plain HTTP is prohibited.

package hitrust.encryption_in_transit

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Minimum TLS version required
min_tls_version := "1.2"

# Approved cipher suites (strong encryption only)
approved_cipher_suites := [
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_AES_256_GCM_SHA384",
	"TLS_AES_128_GCM_SHA256",
]

# Environments requiring strict TLS enforcement
protected_environments := ["production", "prod", "staging", "uat", "phi", "healthcare"]

# --- POLICY RULES ---

# Deny connectors configured with plain HTTP URLs
deny[msg] {
	connector := input.connector
	connector.spec.url
	startswith(connector.spec.url, "http://")

	msg := sprintf(
		"HITRUST 09.02.a Violation: Connector '%s' uses unencrypted HTTP ('%s'). All connections that may transmit PHI must use HTTPS/TLS to protect data in transit and prevent eavesdropping.",
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
		"HITRUST 09.02.a Violation: Docker registry connector '%s' uses unencrypted HTTP ('%s'). Healthcare artifact registries must use HTTPS/TLS to protect container images and metadata.",
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
		"HITRUST 09.02.a Violation: HTTP step '%s' in stage '%s' uses unencrypted URL '%s'. All API calls that may transmit PHI must use HTTPS/TLS to ensure confidentiality and integrity.",
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
		"HITRUST 09.02.a Violation: Shell step '%s' in stage '%s' references a plain HTTP URL. All external connections in scripts that may transmit PHI must use HTTPS/TLS.",
		[step.name, stage.name],
	)
}

# Deny deployments to protected environments without TLS configuration
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_protected_environment(env_ref)

	not has_tls_enabled(stage)

	msg := sprintf(
		"HITRUST 09.02.a Violation: Deployment stage '%s' deploys to protected environment '%s' without TLS configuration. All services handling PHI must enforce encryption in transit to protect patient data.",
		[stage.name, env_ref],
	)
}

# Deny TLS versions below 1.2
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.spec.tlsVersion
	step.spec.tlsVersion < min_tls_version

	msg := sprintf(
		"HITRUST 09.02.b Violation: Step '%s' in stage '%s' uses TLS version '%s' which is below the required minimum '%s'. Healthcare systems must use TLS 1.2 or higher due to known vulnerabilities in older versions (POODLE, BEAST).",
		[step.name, stage.name, step.spec.tlsVersion, min_tls_version],
	)
}

# Warn about missing certificate validation
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "Http"
	step.spec.url
	startswith(step.spec.url, "https://")

	step.spec.certificateCheck == false

	msg := sprintf(
		"HITRUST 09.02.a Warning: HTTP step '%s' in stage '%s' has certificate validation disabled. Disabling certificate checks exposes the connection to man-in-the-middle attacks. Only disable for non-production testing environments.",
		[step.name, stage.name],
	)
}

# Warn about shell scripts with insecure curl/wget flags
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	step.spec.source.spec.script

	has_insecure_curl_flag(step.spec.source.spec.script)

	msg := sprintf(
		"HITRUST 09.02.a Warning: Shell step '%s' in stage '%s' uses insecure curl/wget flags (-k, --insecure, --no-check-certificate). These flags disable certificate validation and expose connections to man-in-the-middle attacks.",
		[step.name, stage.name],
	)
}

# --- HELPER RULES ---

is_protected_environment(env_ref) if {
	some protected in protected_environments
	contains(lower(env_ref), protected)
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

has_insecure_curl_flag(script) if {
	contains(script, "curl")
	contains(script, "-k")
}

has_insecure_curl_flag(script) if {
	contains(script, "curl")
	contains(script, "--insecure")
}

has_insecure_curl_flag(script) if {
	contains(script, "wget")
	contains(script, "--no-check-certificate")
}
