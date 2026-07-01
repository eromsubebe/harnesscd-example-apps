# SOC 2 CC6.3 - Logical and Physical Access Controls
# Ensures build artifacts are pushed only to approved, encrypted artifact registries.
# Blocks publishing to public or unapproved registries.

package soc2.cc6_3_approved_registries

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Approved artifact registries (only these are allowed for pushing build artifacts)
approved_registries := [
	"https://your-org.jfrog.io",
	"https://us-docker.pkg.dev/your-project",
	"https://your-org.azurecr.io",
]

# Blocked public/unapproved registries
blocked_registries := [
	"docker.io",
	"registry.hub.docker.com",
	"ghcr.io",
	"public.ecr.aws",
]

# --- POLICY RULES ---

# Deny build/push steps that target a blocked public registry
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in ["BuildAndPushDockerRegistry", "BuildAndPushECR", "BuildAndPushACR", "BuildAndPushGCR"]

	registry_url := step.spec.connectorRef.spec.dockerRegistryUrl
	some blocked in blocked_registries
	contains(lower(registry_url), blocked)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Build step '%s' in stage '%s' pushes artifacts to blocked public registry '%s'. Artifacts must only be stored in approved, encrypted registries.",
		[step.name, stage.name, registry_url],
	)
}

# Deny build/push steps that target a registry not in the approved list
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in ["BuildAndPushDockerRegistry", "BuildAndPushECR", "BuildAndPushACR", "BuildAndPushGCR"]

	registry_url := step.spec.connectorRef.spec.dockerRegistryUrl
	not is_approved_registry(registry_url)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Build step '%s' in stage '%s' pushes artifacts to unapproved registry '%s'. Only approved encrypted registries are permitted: %s.",
		[step.name, stage.name, registry_url, concat(", ", approved_registries)],
	)
}

# Deny Docker registry connectors pointing to blocked registries
deny[msg] {
	connector := input.connector
	connector.type == "DockerRegistry"

	some blocked in blocked_registries
	contains(lower(connector.spec.dockerRegistryUrl), blocked)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Docker connector '%s' references blocked public registry '%s'. Only approved, encrypted artifact registries may be configured.",
		[connector.name, connector.spec.dockerRegistryUrl],
	)
}

# Deny Docker registry connectors not in the approved list
deny[msg] {
	connector := input.connector
	connector.type == "DockerRegistry"

	connector.spec.dockerRegistryUrl
	not is_approved_registry(connector.spec.dockerRegistryUrl)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Docker connector '%s' uses unapproved registry '%s'. Artifact registries must be from the approved list: %s.",
		[connector.name, connector.spec.dockerRegistryUrl, concat(", ", approved_registries)],
	)
}

# --- HELPER RULES ---

is_approved_registry(url) if {
	some approved in approved_registries
	startswith(lower(url), lower(approved))
}
