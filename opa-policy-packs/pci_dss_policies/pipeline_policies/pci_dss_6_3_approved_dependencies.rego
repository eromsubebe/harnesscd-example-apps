# PCI DSS v4.0 - Requirement 6.3.2
# "An inventory of bespoke and custom software, and third-party software components
#  incorporated into bespoke and custom software is maintained to facilitate
#  vulnerability and patch management."
#
# Dependencies pulled during builds must come from approved, vetted registries.
# Pulling directly from public sources (npm, PyPI, Docker Hub, Maven Central) is a
# supply chain attack vector. All third-party components must be sourced from
# internal mirrors where they are inventoried and scanned.

package pci_dss.req6_approved_dependencies

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
approved_registries := [
	"your-org.jfrog.io",
	"us-docker.pkg.dev/your-project",
	"your-org.azurecr.io",
	"nexus.your-org.com",
	"artifactory.your-org.com",
]

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
		"PCI DSS 6.3.2 Violation: Step '%s' in stage '%s' pulls image from unvetted public registry '%s'. All third-party components must be sourced from approved internal registries to maintain inventory and facilitate patch management.",
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
		"PCI DSS 6.3.2 Violation: CI stage '%s' uses a runtime image from unvetted registry '%s'. Build environments must use approved, internally-maintained base images.",
		[stage.name, blocked],
	)
}

# Deny shell/run steps that install packages directly from public registries
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "Run"
	step.spec.command

	some blocked in blocked_registries
	contains(lower(step.spec.command), blocked)

	msg := sprintf(
		"PCI DSS 6.3.2 Violation: Run step '%s' in stage '%s' references public registry '%s'. Package installations must use approved internal mirrors, not direct public sources.",
		[step.name, stage.name, blocked],
	)
}

deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type == "ShellScript"
	step.spec.source.spec.script

	some blocked in blocked_registries
	contains(lower(step.spec.source.spec.script), blocked)

	msg := sprintf(
		"PCI DSS 6.3.2 Violation: Shell step '%s' in stage '%s' references public registry '%s'. Dependencies must be pulled from approved mirrors for inventory tracking and vulnerability management.",
		[step.name, stage.name, blocked],
	)
}

# Deny mutable image tags (no version pinning)
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	image := step.spec.image
	image != ""

	tag := split(image, ":")[minus(count(split(image, ":")), 1)]
	tag in blocked_tags

	msg := sprintf(
		"PCI DSS 6.3.2 Violation: Step '%s' in stage '%s' uses mutable image tag '%s' (image: '%s'). Third-party components must be pinned to specific versions or SHA256 digests for reproducibility and patch tracking.",
		[step.name, stage.name, tag, image],
	)
}

# Deny build steps using base images from blocked registries
deny[msg] {
	stage := input.pipeline.stages[_].stage
	step := stage.spec.execution.steps[_].step
	step.type in ["BuildAndPushDockerRegistry", "BuildAndPushECR", "BuildAndPushACR", "BuildAndPushGCR"]
	step.spec.baseImageConnectorRef

	some blocked in blocked_registries
	contains(lower(step.spec.baseImageConnectorRef), blocked)

	msg := sprintf(
		"PCI DSS 6.3.2 Violation: Build step '%s' in stage '%s' uses a base image from unvetted registry '%s'. Docker base images must come from approved internal registries.",
		[step.name, stage.name, blocked],
	)
}
