# SOC 2 CC6.3 - Logical and Physical Access Controls
# Ensures connectors only target allowlisted external destinations.
# Prevents unauthorized outbound connections from pipeline infrastructure.

package soc2.cc6_3_connector_allowlist

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Allowlisted destination domains for connectors
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

# Deny connectors pointing to non-allowlisted external URLs
deny[msg] {
	connector := input.connector
	connector.spec.url

	not url_matches_allowlist(connector.spec.url)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Connector '%s' targets '%s' which is not in the allowlisted destinations. All external service connections must use approved endpoints.",
		[connector.name, connector.spec.url],
	)
}

# Deny connectors pointing to explicitly blocked destinations
deny[msg] {
	connector := input.connector
	connector.spec.url

	some blocked in blocked_domains
	contains(lower(connector.spec.url), blocked)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Connector '%s' targets blocked destination '%s'. Connections to unauthorized or high-risk endpoints are prohibited.",
		[connector.name, blocked],
	)
}

# Deny Docker registry connectors pointing to non-allowlisted registries
deny[msg] {
	connector := input.connector
	connector.type == "DockerRegistry"
	connector.spec.dockerRegistryUrl

	not url_matches_allowlist(connector.spec.dockerRegistryUrl)

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Docker registry connector '%s' targets '%s' which is not in the allowlisted destinations. Artifact registries must be approved endpoints.",
		[connector.name, connector.spec.dockerRegistryUrl],
	)
}

# --- HELPER RULES ---

url_matches_allowlist(url) if {
	some domain in allowlisted_domains
	contains(lower(url), lower(domain))
}
