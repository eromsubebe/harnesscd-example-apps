# HITRUST CSF v11 - 01.03 User Authentication for External Connections
# Control Reference: 01.03.a, 01.03.b
# Maps to: ISO/IEC 27001:2013 A.9.2.1, NIST CSF PR.AC-7, HIPAA 164.312(d)
#
# Requirement: Appropriate authentication methods are used to control access by
# remote users. Multi-factor authentication is used for remote access to the
# organization's network.
#
# Rule: All API connectors that may access PHI must use strong authentication
# (API tokens, OAuth, certificate-based) and must not allow unauthenticated or
# anonymous access.

package hitrust.secure_authentication

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Healthcare/FHIR API endpoints that handle PHI
phi_api_patterns := [
	"fhir",
	"hl7",
	"phi",
	"healthcare",
	"patient",
	"medical",
	"hipaa",
	"hitrust",
	"epic",
	"cerner",
	"allscripts",
]

# Approved authentication types for PHI API access
approved_auth_types := [
	"Bearer",
	"OAuth",
	"ApiKey",
	"ServiceAccount",
	"Certificate",
	"JWT",
]

# Weak authentication types that require additional security
weak_auth_types := [
	"UsernamePassword",
	"BasicAuth",
]

# Blocked authentication types (insecure or anonymous)
blocked_auth_types := [
	"Anonymous",
	"None",
]

# --- POLICY RULES ---

# Deny connectors to PHI APIs without authentication
deny[msg] {
	connector := input.connector
	connector.type in ["Http", "CustomHealth", "Custom"]
	connector.spec.url

	is_phi_api(connector.spec.url)

	not has_authentication(connector)

	msg := sprintf(
		"HITRUST 01.03.a Violation: Connector '%s' accesses PHI API endpoint '%s' without authentication. All external connections to ePHI systems must use strong authentication mechanisms (OAuth, API tokens, certificates).",
		[connector.name, connector.spec.url],
	)
}

# Deny connectors using anonymous or insecure authentication
deny[msg] {
	connector := input.connector
	connector.spec.url

	is_phi_api(connector.spec.url)

	connector.spec.auth
	connector.spec.auth.type in blocked_auth_types

	msg := sprintf(
		"HITRUST 01.03.a Violation: Connector '%s' uses '%s' authentication to access PHI API endpoint '%s'. Anonymous or unauthenticated access to ePHI is strictly prohibited under HITRUST controls.",
		[connector.name, connector.spec.auth.type, connector.spec.url],
	)
}

# Warn about weak authentication methods
deny[msg] {
	connector := input.connector
	connector.spec.url

	is_phi_api(connector.spec.url)

	connector.spec.auth.type in weak_auth_types

	msg := sprintf(
		"HITRUST 01.03.b Warning: Connector '%s' uses weak authentication method '%s' to access PHI API endpoint '%s'. Consider upgrading to OAuth, API tokens, or certificate-based authentication for stronger security. If using username/password, ensure it's combined with TLS and stored in a secure vault.",
		[connector.name, connector.spec.auth.type, connector.spec.url],
	)
}

# Deny connectors to PHI APIs using basic auth without TLS
deny[msg] {
	connector := input.connector
	connector.spec.url

	is_phi_api(connector.spec.url)

	connector.spec.auth.type in weak_auth_types
	not startswith(connector.spec.url, "https://")

	msg := sprintf(
		"HITRUST 01.03.a Violation: Connector '%s' uses basic authentication to PHI API endpoint '%s' over plain HTTP. Credentials and ePHI must be transmitted over HTTPS/TLS only to prevent credential theft and data interception.",
		[connector.name, connector.spec.url],
	)
}

# Deny connectors with hardcoded credentials instead of secrets
deny[msg] {
	connector := input.connector
	connector.spec.url

	is_phi_api(connector.spec.url)

	connector.spec.auth.spec.passwordRef
	not contains(connector.spec.auth.spec.passwordRef, "secret")
	not contains(connector.spec.auth.spec.passwordRef, "vault")

	msg := sprintf(
		"HITRUST 01.03.b Violation: Connector '%s' accessing PHI API endpoint '%s' has hardcoded credentials. All authentication credentials for ePHI systems must be stored in secure secret management (Harness Secrets, HashiCorp Vault, AWS Secrets Manager) to prevent credential exposure.",
		[connector.name, connector.spec.url],
	)
}

# Warn about missing multi-factor authentication indicators
deny[msg] {
	connector := input.connector
	connector.spec.url

	is_phi_api(connector.spec.url)

	has_authentication(connector)

	not has_mfa_indicator(connector)

	msg := sprintf(
		"HITRUST 01.03.b Warning: Connector '%s' accessing PHI API endpoint '%s' does not indicate multi-factor authentication (MFA). HITRUST recommends MFA for remote access to PHI systems. Consider OAuth flows with MFA or certificate-based authentication.",
		[connector.name, connector.spec.url],
	)
}

# Deny connectors without IP allowlisting or delegate selectors
deny[msg] {
	connector := input.connector
	connector.spec.url

	is_phi_api(connector.spec.url)

	not has_network_restriction(connector)

	msg := sprintf(
		"HITRUST 01.03.a Violation: Connector '%s' accessing PHI API endpoint '%s' has no network access restrictions (IP allowlisting, delegate selectors). Remote access to PHI systems should be restricted to known source networks to reduce attack surface.",
		[connector.name, connector.spec.url],
	)
}

# --- HELPER RULES ---

is_phi_api(url) if {
	some pattern in phi_api_patterns
	contains(lower(url), pattern)
}

has_authentication(connector) if {
	connector.spec.auth
	connector.spec.auth.type
	connector.spec.auth.type in approved_auth_types
}

has_authentication(connector) if {
	connector.spec.auth
	connector.spec.auth.type in weak_auth_types
	startswith(connector.spec.url, "https://")
}

has_mfa_indicator(connector) if {
	connector.spec.auth.type == "OAuth"
}

has_mfa_indicator(connector) if {
	connector.spec.auth.type == "Certificate"
}

has_mfa_indicator(connector) if {
	connector.spec.auth.type == "ServiceAccount"
}

has_mfa_indicator(connector) if {
	connector.tags
	connector.tags["mfa-enabled"] == "true"
}

has_network_restriction(connector) if {
	connector.spec.executeOnDelegate
	connector.spec.delegateSelectors
	count(connector.spec.delegateSelectors) > 0
}

has_network_restriction(connector) if {
	connector.spec.ipAllowlist
	count(connector.spec.ipAllowlist) > 0
}

has_network_restriction(connector) if {
	connector.spec.allowedSourceNetworks
	count(connector.spec.allowedSourceNetworks) > 0
}
