# PCI DSS v4.0 - Requirement 6.2.3 / 6.5.1
# "Bespoke and custom software is reviewed prior to being released into production
#  or to customers, to identify and correct potential coding vulnerabilities."
# "Changes to all software components on production systems are made according to
#  established processes — including code review by a party other than the author."
#
# Ensures pipelines are backed by version control (git) so that all code changes
# pass through a pull request review process before they can be deployed. A pipeline
# not stored in git has no audit trail proving independent code review occurred.

package pci_dss.req6_code_review_required

import future.keywords.if

# --- POLICY RULES ---

# Deny pipelines not stored in git (no code review audit trail)
deny[msg] {
	not input.pipeline.gitConfig

	msg := sprintf(
		"PCI DSS 6.2.3 Violation: Pipeline '%s' is not backed by version control (no gitConfig). All pipeline definitions and code changes must pass through a documented code review process (pull request) before deployment to production.",
		[input.pipeline.name],
	)
}

# Deny pipelines in git but without a branch specified (ambiguous source)
deny[msg] {
	input.pipeline.gitConfig
	not input.pipeline.gitConfig.branch

	msg := sprintf(
		"PCI DSS 6.5.1 Violation: Pipeline '%s' has gitConfig but no branch specified. The pipeline must reference a specific branch to ensure it executes the reviewed, approved version of the definition.",
		[input.pipeline.name],
	)
}

# Deny pipelines in git but without a connector reference (unverified source)
deny[msg] {
	input.pipeline.gitConfig
	not input.pipeline.gitConfig.connectorRef

	msg := sprintf(
		"PCI DSS 6.5.1 Violation: Pipeline '%s' has gitConfig but no connectorRef. A valid git connector must be specified to prove the pipeline definition is sourced from an authorized, authenticated repository.",
		[input.pipeline.name],
	)
}

# Deny pipelines in git but without a file path (cannot verify what was reviewed)
deny[msg] {
	input.pipeline.gitConfig
	not input.pipeline.gitConfig.filePath

	msg := sprintf(
		"PCI DSS 6.5.1 Violation: Pipeline '%s' has gitConfig but no filePath. The exact file path must be declared so the executing definition can be matched to the version-controlled artifact that underwent code review.",
		[input.pipeline.name],
	)
}
