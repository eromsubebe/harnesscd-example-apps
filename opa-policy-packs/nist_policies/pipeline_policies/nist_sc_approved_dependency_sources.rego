# NIST CSF 2.0 - GV.SC (Supply Chain Risk Management)
# Rule: Dependencies pulled during a build must come from approved, trusted registries or mirrors.
# Pulling from arbitrary public sources is a threat vector for supply chain attacks.
# Covers npm packages, Maven artifacts, Docker base images, and other dependencies.

package nist.sc_approved_dependency_sources

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Approved dependency registries/mirrors
approved_registries := [
	"your-org.jfrog.io",
	"us-docker.pkg.dev/your-project",
	"your-org.azurecr.io",
	"nexus.your-org.com",
	"artifactory.your-org.com",
]

# Blocked public registries (untrusted sources)
blocked_registries := [
	"docker.io",
	"registry.hub.docker.com",
	"registry.npmjs.org",
	"repo1.maven.org",
	"public.ecr.aws",
	"ghcr.io",
	"pypi.org",
	"rubygems.org",
]

# Blocked mutable image tags (must pin to digest or specific version)
blocked_tags := ["latest", "stable", "main", "master", "dev"]

# --- POLICY RULES ---

# Deny steps using container images from blocked public registries
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.spec.image

	some blocked in blocked_registries
	contains(lower(step.spec.image), blocked)

	msg := sprintf(
		"NIST CSF GV.SC Violation: Step '%s' in stage '%s' pulls image from untrusted public registry '%s'. All dependencies must come from approved, trusted registries or mirrors.",
		[step.name, stage.name, blocked],
	)
}

# Deny CI stage runtime images from blocked registries
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "CI"
	stage.spec.runtime.spec.connectorRef

	some blocked in blocked_registries
	contains(lower(stage.spec.runtime.spec.connectorRef), blocked)

	msg := sprintf(
		"NIST CSF GV.SC Violation: CI stage '%s' uses a runtime image from untrusted public registry '%s'. Build environments must use approved base images.",
		[stage.name, blocked],
	)
}

# Deny shell steps that install packages directly from public registries
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	step.spec.source.spec.script

	some blocked in blocked_registries
	contains(lower(step.spec.source.spec.script), blocked)

	msg := sprintf(
		"NIST CSF GV.SC Violation: Shell step '%s' in stage '%s' references untrusted public registry '%s'. Dependencies must be pulled from approved mirrors, not directly from public sources.",
		[step.name, stage.name, blocked],
	)
}

# Deny Run steps that install packages directly from public registries
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "Run"
	step.spec.command

	some blocked in blocked_registries
	contains(lower(step.spec.command), blocked)

	msg := sprintf(
		"NIST CSF GV.SC Violation: Run step '%s' in stage '%s' references untrusted public registry '%s'. Dependencies must be pulled from approved mirrors, not directly from public sources.",
		[step.name, stage.name, blocked],
	)
}

# Deny steps using mutable image tags (no version pinning)
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	image := step.spec.image
	image != ""

	tag := split(image, ":")[minus(count(split(image, ":")), 1)]
	tag in blocked_tags

	msg := sprintf(
		"NIST CSF GV.SC Violation: Step '%s' in stage '%s' uses mutable image tag '%s' (image: '%s'). Dependencies must be pinned to specific versions or SHA256 digests to ensure supply chain integrity.",
		[step.name, stage.name, tag, image],
	)
}

# Deny build/push steps pulling base images from blocked registries
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in ["BuildAndPushDockerRegistry", "BuildAndPushECR", "BuildAndPushACR", "BuildAndPushGCR"]
	step.spec.baseImageConnectorRef

	some blocked in blocked_registries
	contains(lower(step.spec.baseImageConnectorRef), blocked)

	msg := sprintf(
		"NIST CSF GV.SC Violation: Build step '%s' in stage '%s' uses a base image from untrusted registry '%s'. Docker base images must come from approved internal registries.",
		[step.name, stage.name, blocked],
	)
}
