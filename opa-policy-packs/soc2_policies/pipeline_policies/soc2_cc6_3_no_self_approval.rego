# SOC 2 CC6.3 - Logical and Physical Access Controls
# Enforces separation of duties by preventing the pipeline executor from
# approving their own deployment to sensitive environments.

package soc2.cc6_3_no_self_approval

import future.keywords.in
import future.keywords.if

# --- CONFIGURABLE PARAMETERS ---
# Environments where self-approval is prohibited
sensitive_environments := ["production", "prod", "staging", "stg", "uat"]

# --- POLICY RULES ---

# Deny HarnessApproval steps that allow the pipeline executor to approve their own deployment
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_sensitive_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "HarnessApproval"
	step.spec.approvers.disallowPipelineExecutor != true

	msg := sprintf(
		"SOC 2 CC6.3 Violation: Approval step '%s' in deployment stage '%s' (environment '%s') does not prevent self-approval. The pipeline executor must not be allowed to approve their own deployment. Set 'disallowPipelineExecutor' to true.",
		[step.name, stage.name, env_ref],
	)
}

# Deny JiraApproval steps that allow the pipeline executor to approve their own deployment
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_sensitive_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "JiraApproval"
	step.spec.approvers.disallowPipelineExecutor != true

	msg := sprintf(
		"SOC 2 CC6.3 Violation: JiraApproval step '%s' in deployment stage '%s' (environment '%s') does not prevent self-approval. The pipeline executor must not be allowed to approve their own deployment. Set 'disallowPipelineExecutor' to true.",
		[step.name, stage.name, env_ref],
	)
}

# Deny ServiceNowApproval steps that allow the pipeline executor to approve their own deployment
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_sensitive_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "ServiceNowApproval"
	step.spec.approvers.disallowPipelineExecutor != true

	msg := sprintf(
		"SOC 2 CC6.3 Violation: ServiceNowApproval step '%s' in deployment stage '%s' (environment '%s') does not prevent self-approval. The pipeline executor must not be allowed to approve their own deployment. Set 'disallowPipelineExecutor' to true.",
		[step.name, stage.name, env_ref],
	)
}

# Deny CustomApproval steps that allow the pipeline executor to approve their own deployment
deny[msg] {
	stage := input.pipeline.stages[_].stage
	stage.type == "Deployment"

	env_ref := stage.spec.environment.environmentRef
	is_sensitive_environment(env_ref)

	step := stage.spec.execution.steps[_].step
	step.type == "CustomApproval"
	step.spec.approvers.disallowPipelineExecutor != true

	msg := sprintf(
		"SOC 2 CC6.3 Violation: CustomApproval step '%s' in deployment stage '%s' (environment '%s') does not prevent self-approval. The pipeline executor must not be allowed to approve their own deployment. Set 'disallowPipelineExecutor' to true.",
		[step.name, stage.name, env_ref],
	)
}

# --- HELPER RULES ---

is_sensitive_environment(env_ref) if {
	some env in sensitive_environments
	contains(lower(env_ref), env)
}
