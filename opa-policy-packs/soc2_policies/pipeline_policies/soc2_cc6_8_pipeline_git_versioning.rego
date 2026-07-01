# SOC 2 CC6.8 - Malicious Software Prevention
# Rule: Are pipeline configuration changes (edits to pipeline YAML/definitions) versioned and auditable?
# Ensures pipelines are stored in git via gitConfig, providing version control,
# change history, and auditability for all pipeline definition changes.

package pipeline.soc2_cc6_8_pipeline_git_versioning

import future.keywords.if

# --- POLICY RULES ---

# Deny pipelines that are not stored in git (missing gitConfig)
deny[msg] {
	not input.pipeline.gitConfig

	msg := sprintf(
		"SOC 2 CC6.8 Violation: Pipeline '%s' is not stored in git (no gitConfig configured). Pipeline definitions must be version-controlled in git to ensure all configuration changes are auditable and traceable.",
		[input.pipeline.name],
	)
}
