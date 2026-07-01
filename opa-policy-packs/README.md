# Harness Policy Packs

Pre-written OPA/Rego policies for automated compliance governance in your CI/CD pipelines.

Compliance is often a bottleneck in modern software delivery. Security and governance teams struggle to keep up with release velocity, while developers find writing Rego policies from scratch time-consuming and error-prone. **Policy Packs solve this problem** by providing production-ready policies that you can adopt with minimal customization, letting your teams focus on shipping features rather than writing governance code.

This repository contains **OPA/Rego policies mapped to 5 industry compliance frameworks**, covering the most common controls organizations need to satisfy during audits.

> **🔄 Living Repository:** We continuously update this repository with new policies, bug fixes, and improvements based on customer feedback and evolving compliance requirements. Watch this repo or check back regularly for updates.

---

## Why Policy Packs?

**The Problem:**
- Writing Rego from scratch requires specialized knowledge and weeks of iteration
- Manual compliance checkpoints create bottlenecks and "compliance fatigue"
- Point-in-time audits leave gaps between checks
- Proving continuous compliance requires manual evidence collection

**The Solution:**
- Copy production-ready policies and customize parameters (environment names, tool types, thresholds)
- Automated enforcement at every pipeline execution—no manual checkpoints
- Continuous compliance with tamper-proof audit trails
- Every pipeline run generates evidence for your GRC team

---

## Frameworks Covered

| Framework | Focus Area | Industry |
|-----------|------------|----------|
| **SOC 2** | Trust service criteria — security, availability, processing integrity | SaaS, Cloud Services |
| **NIST** | SP 800-53, 800-171 — configuration management, supply chain risk | Government, Defense |
| **PCI DSS** | Payment card data — vulnerability management, secrets management | Financial Services, E-commerce |
| **HIPAA** | Protected health information — data leakage prevention, secure APIs | Healthcare |
| **HITRUST** | Healthcare security — audit controls, change management | Healthcare |

---

## Repository Structure

```
.
├── hipaa_policies/
│   ├── pipeline_policies/
│   └── connector_policies/
├── hitrust_policies/
│   ├── pipeline_policies/
│   └── connector_policies/
├── nist_policies/
│   └── pipeline_policies/
├── pci_dss_policies/
│   └── pipeline_policies/
└── soc2_policies/
    ├── pipeline_policies/
    └── connector_policies/
```

Policies are organized by entity type:
- **`pipeline_policies/`** — Enforce controls on CI/CD pipelines
- **`connector_policies/`** — Enforce controls on external integrations

---

## How Policies Map to Framework Controls

Policies in this repository enforce specific compliance controls by validating pipeline configurations and blocking non-compliant behavior. Here's how framework requirements translate to DevOps enforcement:

| Framework Control | What It Requires | How Policy Enforces It |
|-------------------|------------------|------------------------|
| **SOC 2 CC6.3** — Change Management | Independent approval before production deployment | Blocks pipelines where `includePipelineExecutionHistory: true` (self-approval) |
| **NIST PR.AA** — Separation of Duties | Code author ≠ deployment approver | Requires minimum 2 distinct approvers from separate user groups |
| **HIPAA 164.312(e)(1)** — Transmission Security | Encrypt PHI in transit | Blocks `http://` URLs, enforces TLS 1.2+ for healthcare endpoints |
| **PCI DSS 6.2.4** — Secure Development | Scan code for vulnerabilities before deployment | Requires container scan, SCA, and SAST steps before deployment stages |
| **HITRUST 09.09** — Malware Protection | Detect malicious code in artifacts | Blocks deployments without preceding security scans; prevents scan suppression |

Each policy file includes:
- **Control reference** — The specific framework requirement it satisfies
- **Configurable parameters** — Environment names, tool types, thresholds
- **Clear violation messages** — What failed and how to fix it

---

## Getting Started

### 1. Choose Your Framework

Select the folder matching your compliance requirements:

| Your Industry | Start Here |
|---------------|------------|
| Healthcare | `hipaa_policies/` or `hitrust_policies/` |
| Financial Services | `pci_dss_policies/` or `soc2_policies/` |
| SaaS / Cloud | `soc2_policies/` |
| Government / Defense | `nist_policies/` |

### 2. Review Policy Files

Open a policy file (e.g., `soc2_policies/pipeline_policies/soc2_cc6_3_no_self_approval.rego`). You'll see:

```rego
# SOC 2 CC6.3 - Logical and Physical Access Controls
# Rule: Prevent self-approval of production deployments

package soc2.cc6_3_no_self_approval

# --- CONFIGURABLE PARAMETERS ---
protected_environments := ["production", "prod", "staging"]
min_approvers := 2

# --- POLICY RULES ---
deny[msg] {
  # ... validation logic
}
```

### 3. Customize Parameters

Update the parameters section to match your organization:

```rego
# Change environment names to yours
protected_environments := ["prod-us-east", "prod-eu-west"]

# Adjust based on team size
min_approvers := 1  # for small teams
```

### 4. Deploy to Harness

Upload the policy file via Harness UI:

```
Harness Account Settings 
  → Security and Governance 
  → Policies 
  → New Policy 
  → Upload .rego file
```

Set the policy type (Pipeline or Connector) and enforcement level.

### 5. Start with Audit Mode

**Critical:** Don't start with enforcement immediately.

1. Set policy enforcement to **"Warning Only"**
2. Run your pipelines normally
3. Review violation reports in Harness
4. Fix common issues (rename environments, update approval steps)
5. Once violations are resolved, switch to **"On Error"**

This phased approach prevents blocking your team while you tune policies.

---

## Common Policy Patterns

### 1. Separation of Duties / No Self-Approval

**What it enforces:**  
The person who writes and commits code cannot approve deployment to production. This satisfies SOC 2, NIST, and HITRUST requirements for independent review.

**How it works:**  
Checks if `includePipelineExecutionHistory: true` in approval steps (which allows self-approval). Also validates that minimum number of distinct approvers are required.

**Example violation:**
```yaml
# ❌ BLOCKED: Pipeline executor can approve their own deployment
- step:
    type: HarnessApproval
    spec:
      includePipelineExecutionHistory: true
```

**Compliant configuration:**
```yaml
# ✅ ALLOWED: Independent approval required
- step:
    type: HarnessApproval
    spec:
      includePipelineExecutionHistory: false
      approvers:
        userGroups: ["Security_Team", "SRE_Team"]
      minimumCount: 2
```

**Policies:**
- `soc2_policies/pipeline_policies/soc2_cc6_3_no_self_approval.rego`
- `nist_policies/pipeline_policies/nist_pr_aa_separation_of_duties.rego`
- `hitrust_policies/pipeline_policies/hitrust_01_01_access_control_separation_of_duties.rego`

---

### 2. Vulnerability Scanning Required

**What it enforces:**  
All deployments to production must have preceding security scans (container image scan, dependency scan, SAST).

**How it works:**  
Checks if deployment stages have preceding stages with scan steps. Looks for step types like `AquaTrivy`, `Snyk`, `Wiz`, or steps with names containing "scan".

**Example violation:**
```yaml
# ❌ BLOCKED: Deployment without security scan
stages:
  - stage:
      name: Deploy_Production
      type: Deployment
      spec:
        environment:
          environmentRef: production
```

**Compliant configuration:**
```yaml
# ✅ ALLOWED: Scan before deployment
stages:
  - stage:
      name: Security_Scan
      type: CI
      spec:
        execution:
          steps:
            - step:
                type: AquaTrivy
                name: Container_Scan
  - stage:
      name: Deploy_Production
      type: Deployment
      spec:
        environment:
          environmentRef: production
```

**Policies:**
- `hipaa_policies/pipeline_policies/hipaa_164_312_vulnerability_management.rego`
- `pci_dss_policies/pipeline_policies/pci_dss_6_2_container_scan_required.rego`
- `soc2_policies/pipeline_policies/soc2_cc6_8_image_scan_before_deploy.rego`

---

## Customization Examples

All policies are designed to be customized for your organization. Here are common customizations:

### Update Environment Names

```rego
# Default
protected_environments := ["production", "prod", "staging", "uat"]

# Customize to match your naming
protected_environments := ["prod-us-east-1", "prod-eu-west-1", "staging"]
```

### Adjust Approval Requirements

```rego
# Default (enterprise scale)
min_approvers := 2

# Small team
min_approvers := 1
```

### Add Your Security Tools

```rego
# Default scan tools
container_scan_step_types := ["AquaTrivy", "Wiz", "Snyk", "Prisma", "Security"]

# Add your scanner
container_scan_step_types := ["AquaTrivy", "Wiz", "Snyk", "Prisma", "Security", "CustomScanner"]
```

### Allowlist Your Services

```rego
# Default
allowlisted_domains := ["your-org.jfrog.io", "github.com"]

# Add your approved destinations
allowlisted_domains := [
  "acme-corp.jfrog.io",
  "github.com",
  "acme-corp.snowflakecomputing.com"
]
```

---

## Testing Policies in Harness

Before enforcing policies in production, test them using the **OPA Playground** built into Harness.

### Using the Harness OPA Playground

1. **Navigate to the OPA Playground:**
   ```
   Harness Account Settings 
     → Security and Governance 
     → Policies 
     → Test Policy (OPA Playground button)
   ```

2. **Upload or paste your policy:**
   - Copy the `.rego` file contents from this repository
   - Paste into the left panel of the playground

3. **Provide test input:**
   Create a sample pipeline YAML in the right panel:
   ```yaml
   pipeline:
     name: Test_Pipeline
     stages:
       - stage:
           name: Deploy_Production
           type: Deployment
           spec:
             environment:
               environmentRef: production
   ```

4. **Run evaluation:**
   - Click **"Evaluate"**
   - Review the output in the bottom panel
   - If the policy triggers a denial, you'll see the violation message
   - If the policy passes, the output will be empty

5. **Iterate and refine:**
   - Adjust the policy parameters (environment names, tool types)
   - Test different pipeline configurations
   - Validate that your policies catch violations without false positives

### Example Test Scenarios

**Test 1: Deployment without approval (should fail)**
```yaml
pipeline:
  name: Test_No_Approval
  stages:
    - stage:
        name: Deploy_Production
        type: Deployment
        spec:
          environment:
            environmentRef: production
```

**Test 2: Deployment with approval (should pass)**
```yaml
pipeline:
  name: Test_With_Approval
  stages:
    - stage:
        name: Approval_Stage
        type: Approval
        spec:
          execution:
            steps:
              - step:
                  type: HarnessApproval
                  spec:
                    includePipelineExecutionHistory: false
                    approvers:
                      userGroups: ["Security_Team"]
    - stage:
        name: Deploy_Production
        type: Deployment
        spec:
          environment:
            environmentRef: production
```

The OPA Playground gives you instant feedback without needing to install anything locally.

---

## Frequently Asked Questions

### What happens when a policy is violated?

The behavior depends on the enforcement level you set in Harness:
- **"Warning Only"** — Pipeline proceeds, violation is logged
- **"On Error"** — Pipeline is blocked, violation message shown to user

### Can I use multiple frameworks together?

Yes! Many organizations layer multiple frameworks. For example:
- Healthcare orgs often use **HIPAA + HITRUST**
- Financial services use **PCI DSS + SOC 2**
- Government contractors use **NIST + SOC 2**

Policies from different frameworks can be applied to the same pipelines without conflict.

### How do I handle false positives?

1. Check if your environment names match the policy's `protected_environments` list
2. Verify your tool names are in the `*_scan_step_types` arrays
3. Customize the policy parameters to match your setup
4. If a policy doesn't fit your use case, simply don't deploy it

### Do these policies work with all Harness modules?

Yes! These policies work across:
- **Continuous Integration (CI)**
- **Continuous Delivery (CD)**
- **Feature Flags**
- **Cloud Cost Management**

The same OPA engine enforces policies across all modules.

### How often should I update policies?

- **Review quarterly** — Check if framework requirements changed
- **After failed audits** — Add policies to close identified gaps
- **When tools change** — Update `*_step_types` arrays if you adopt new scanners
- **Version control** — Track changes in Git just like code

---

## Contributing

Contributions welcome! Found a bug or want to add a policy?

1. **Report Issues** — [Open an issue](../../issues)
2. **Submit Pull Requests** — Fork, improve, PR
3. **Share Feedback** — Tell us how you're using these policies

---

## Resources

- **[Harness Policy as Code Documentation](https://developer.harness.io/docs/platform/governance/policy-as-code/)**
- **[OPA/Rego Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)**
- **[Harness Community Slack](https://join.slack.com/t/harnesscommunity/shared_invite/)**

---

## License

These policies are provided as examples and templates. Review and customize them for your organization's specific compliance requirements before production use.

---

<div align="center">

[![Frameworks](https://img.shields.io/badge/frameworks-5-green.svg)]()
[![OPA](https://img.shields.io/badge/OPA-Rego-orange.svg)]()

**[Report an Issue](../../issues)** • **[Harness Docs](https://developer.harness.io/docs/platform/governance/policy-as-code/)**

</div>
