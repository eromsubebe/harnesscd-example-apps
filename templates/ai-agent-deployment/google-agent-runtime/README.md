# Harness Pipeline Templates for ADK Agent Deployment to Agent Runtime

Two pipeline templates for deploying ADK agents to GCP Agent Runtime, each using a different deployment method.

**Template 1: `adk-agentscli-deployment.yaml`** — Uses **Google Agents CLI** (`agents-cli deploy`). Single CI stage that validates, tests, deploys source code directly, and manages canary traffic with rollback. Best for projects scaffolded with `agents-cli create`.

**Template 2: `adk-vertexai-sdk-artifact-deployment.yaml`** — Uses **Vertex AI SDK** with the `container_spec` image URI method. Two stages: CI builds and pushes a Docker image to Google Artifact Registry, CD deploys the container to Agent Runtime via `client.agent_engines.create()`. Includes canary traffic splitting and automatic rollback. Requires `server.py` implementing the BYOC HTTP contract (`/api/reasoning_engine`, `/api/stream_reasoning_engine`).

Both templates require a GCP service account key (`gcp_sa_key_json`) and region (`gcp_region`) as Harness secrets. Template 2 additionally requires a GAR Docker repository and connector.
