# HIPAA Security Rule - 45 CFR § 164.312(a)(2)(i) - Unique User Identification
# Technical Safeguard: Assign a unique name and/or number for identifying and
# tracking user identity when accessing ePHI.
#
# Also relates to: 45 CFR § 164.312(d) - Person or Entity Authentication
#
# Rule: All API connectors that may access PHI must use secure authentication
# (API tokens, OAuth) and must not allow unauthenticated or anonymous access.

package hipaa.secure_api_access

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
]

# Approved authentication types for PHI API access
approved_auth_types := [
	"UsernamePassword",
	"Bearer",
	"OAuth",
	"ApiKey",
	"ServiceAccount",
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
		"HIPAA 164.312(a)(2)(i) Violation: Connector '%s' accesses PHI API endpoint '%s' without authentication. All API access to ePHI must use secure authentication mechanisms (API tokens, OAuth, service accounts).",
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
		"HIPAA 164.312(d) Violation: Connector '%s' uses '%s' authentication to access PHI API endpoint '%s'. Anonymous or unauthenticated access to ePHI is prohibited.",
		[connector.name, connector.spec.auth.type, connector.spec.url],
	)
}

# Deny connectors to PHI APIs using basic auth without TLS
deny[msg] {
	connector := input.connector
	connector.spec.url

	is_phi_api(connector.spec.url)

	connector.spec.auth.type == "UsernamePassword"
	not startswith(connector.spec.url, "https://")

	msg := sprintf(
		"HIPAA 164.312(e)(1) Violation: Connector '%s' uses basic authentication to PHI API endpoint '%s' over plain HTTP. Credentials and ePHI data must be transmitted over HTTPS/TLS only.",
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
		"HIPAA 164.312(a)(2)(iv) Violation: Connector '%s' accessing PHI API endpoint '%s' has hardcoded credentials. All authentication credentials for ePHI systems must be stored in secure secret management (Harness Secrets, Vault).",
		[connector.name, connector.spec.url],
	)
}

# Warn about connectors to PHI APIs without IP allowlisting
deny[msg] {
	connector := input.connector
	connector.spec.url

	is_phi_api(connector.spec.url)

	not has_ip_allowlist(connector)

	msg := sprintf(
		"HIPAA 164.312(a)(1) Warning: Connector '%s' accessing PHI API endpoint '%s' has no IP allowlisting configured. Consider restricting access to known IP ranges to reduce unauthorized access risk.",
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

has_ip_allowlist(connector) if {
	connector.spec.executeOnDelegate
	connector.spec.delegateSelectors
}

has_ip_allowlist(connector) if {
	connector.spec.ipAllowlist
	count(connector.spec.ipAllowlist) > 0
}
