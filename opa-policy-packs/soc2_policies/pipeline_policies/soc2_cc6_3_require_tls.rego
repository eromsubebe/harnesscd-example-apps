# SOC 2 CC6.3 - Logical and Physical Access Controls
# Ensures all external service connections in pipelines use HTTPS/TLS.
# Plain HTTP endpoints are denied to prevent data exposure in transit.

package soc2.cc6_3_require_tls

import future.keywords.in
import future.keywords.if

# --- POLICY RULES ---

# Deny connectors configured with plain HTTP URLs
deny[msg] {
	connector := input.connector
	connector.spec.url
	startswith(connector.spec.url, "http://")

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Connector '%s' uses unencrypted HTTP ('%s'). All external service connections must use HTTPS/TLS to protect data in transit.",
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
		"SOC 2 CC6.3 Violation: Docker registry connector '%s' uses unencrypted HTTP ('%s'). Artifact registries must use HTTPS/TLS.",
		[connector.name, connector.spec.dockerRegistryUrl],
	)
}

# Deny pipeline steps with HTTP webhook/API URLs in their configuration
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "Http"
	step.spec.url
	startswith(step.spec.url, "http://")

	msg := sprintf(
		"SOC 2 CC6.3 Violation: HTTP step '%s' in stage '%s' uses unencrypted URL '%s'. All API calls and webhooks must use HTTPS/TLS.",
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
		"SOC 2 CC6.3 Violation: Shell step '%s' in stage '%s' references a plain HTTP URL. All external connections in scripts must use HTTPS/TLS.",
		[step.name, stage.name],
	)
}

# Deny build/push steps using connectors with plain HTTP registry URLs
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in ["BuildAndPushDockerRegistry", "BuildAndPushECR", "BuildAndPushACR", "BuildAndPushGCR"]
	step.spec.connectorRef.spec.dockerRegistryUrl
	startswith(step.spec.connectorRef.spec.dockerRegistryUrl, "http://")

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Build step '%s' in stage '%s' pushes to a registry over plain HTTP ('%s'). Artifact registries must use HTTPS/TLS.",
		[step.name, stage.name, step.spec.connectorRef.spec.dockerRegistryUrl],
	)
}
