# NIST CSF 2.0 - PR.PS (Platform Security)
# Maps to: PR.PS-01 — The configuration of the platform is managed and secured.
# Maps to: PR.PS-06 — Secure software development practices are integrated, and their
#   performance is monitored throughout the software development life cycle.
# Maps to: GV.PO-01 — Organizational cybersecurity policy is established based on
#   organizational context.
# Maps to: DE.CM-09 — Computing hardware and software, runtime environments, and their
#   data are monitored to find potentially adverse events.
#
# Guidance: Pipeline definitions are executable infrastructure — changes to them can
# alter what gets deployed, bypass security controls, or introduce malicious steps.
# Organizations must ensure that pipeline configurations pass through an approved
# review process (code review via pull request) and that the executing definition
# matches the version-controlled, reviewed artifact. Storing pipelines in git via
# gitConfig ensures all changes are tracked, reviewed, and auditable. Any pipeline
# not backed by git represents drift between declared and executing configuration,
# which is a violation.

package nist.pr_ps_pipeline_version_control

import future.keywords.if

# --- POLICY RULES ---

# Deny pipelines that are not stored in git (no gitConfig present)
deny[msg] {
	not input.pipeline.gitConfig

	msg := sprintf(
		"NIST CSF PR.PS-01 Violation: Pipeline '%s' is not backed by version control (no gitConfig configured). Pipeline definitions must be stored in git to ensure all changes pass through an approved review process and to prevent drift between the declared and executing configuration.",
		[input.pipeline.name],
	)
}

# Deny pipelines stored in git but without a branch specified (ambiguous source of truth)
deny[msg] {
	input.pipeline.gitConfig
	not input.pipeline.gitConfig.branch

	msg := sprintf(
		"NIST CSF PR.PS-06 Violation: Pipeline '%s' has gitConfig but no branch specified. The executing pipeline definition must reference a specific branch to ensure it matches the reviewed, version-controlled artifact.",
		[input.pipeline.name],
	)
}

# Deny pipelines stored in git but without a connector reference (unverified git source)
deny[msg] {
	input.pipeline.gitConfig
	not input.pipeline.gitConfig.connectorRef

	msg := sprintf(
		"NIST CSF GV.PO-01 Violation: Pipeline '%s' has gitConfig but no connectorRef. A valid git connector must be specified to ensure the pipeline definition is sourced from an approved, authenticated repository.",
		[input.pipeline.name],
	)
}

# Deny pipelines stored in git but without a file path (cannot verify artifact identity)
deny[msg] {
	input.pipeline.gitConfig
	not input.pipeline.gitConfig.filePath

	msg := sprintf(
		"NIST CSF DE.CM-09 Violation: Pipeline '%s' has gitConfig but no filePath specified. The exact file path in the repository must be declared to ensure the executing definition matches the version-controlled, reviewed artifact.",
		[input.pipeline.name],
	)
}
