#!/usr/bin/env bash
# setup/create_kb.sh
#
# Creates the S3 bucket, sample policy documents, and IAM role needed for
# the IGA tutorial knowledge base. Populates the agentKnowledgeBase connector OC.
# Generates knowledge_base_query events (v3) when PolicyExplanationAgent retrieves docs.
#
# Two-phase setup:
#   Phase 1 (this script): S3 bucket + policy documents + IAM role (fully automated).
#   Phase 2 (console):     KB + AOSS vector store + data source (see Step 4 below).
#   Phase 3 (this script): ingest + attach to PolicyExplanationAgent (after Phase 2).
#
# Prerequisites: AWS_REGION, AWS_ACCOUNT_ID, PROJECT_PREFIX set in environment.
#   KB_ID must be set before running Phase 3 (set after console KB creation).

set -euo pipefail

KB_BUCKET="${PROJECT_PREFIX}-${AWS_ACCOUNT_ID}-${AWS_REGION}-kb"
KB_ROLE_NAME="${PROJECT_PREFIX}-kb-role"

# ---------------------------------------------------------------------------
echo "=== Phase 1, Step 1: Create KB S3 bucket ==="
# ---------------------------------------------------------------------------

if aws s3api head-bucket --bucket "${KB_BUCKET}" --region "${AWS_REGION}" 2>/dev/null; then
    echo "Bucket ${KB_BUCKET} already exists — skipping."
else
    if [ "${AWS_REGION}" = "us-east-1" ]; then
        aws s3api create-bucket \
            --bucket "${KB_BUCKET}" \
            --region "${AWS_REGION}"
    else
        aws s3api create-bucket \
            --bucket "${KB_BUCKET}" \
            --region "${AWS_REGION}" \
            --create-bucket-configuration "LocationConstraint=${AWS_REGION}"
    fi
    echo "Created: ${KB_BUCKET}"
fi

aws s3api put-public-access-block \
    --bucket "${KB_BUCKET}" \
    --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 1, Step 2: Upload sample IGA policy documents ==="
# ---------------------------------------------------------------------------

mkdir -p /tmp/kb-docs

cat > /tmp/kb-docs/least-privilege-policy.txt << 'DOC'
IGA Policy: Least Privilege Access

Policy ID: IGA-POL-001
Effective Date: 2026-01-01
Owner: Identity Governance Team

1. Principle
   All user and system accounts must be provisioned with the minimum set of permissions
   required to perform their defined job functions. No standing access to privileged
   systems is permitted without time-bound approval.

2. Scope
   This policy applies to all human identities, service accounts, and AI agent identities
   operating within the organization's AWS environment and connected SaaS applications.

3. Application Access
   3.1 Salesforce: Standard users receive Reports:Read by default.
       Admin roles require quarterly certification.
   3.2 Workday: HR data access is restricted to HR business partners and direct managers.
       Worker:Read is granted to all employees for self-service.
   3.3 ServiceNow: ITSM ticket read access is granted by default.
       Admin and change-management roles require approval and annual certification.

4. Privileged Access
   4.1 Privileged access (admin roles, write access to financial systems) requires
       MFA and session assurance level HIGH.
   4.2 Any privileged access granted must be logged and reviewed quarterly.
   4.3 Shared privileged accounts are prohibited. Per-identity accounts are mandatory.

5. AI Agent Access
   5.1 AI agents must operate under named IAM roles or OAuth clients with defined scopes.
   5.2 Agent credentials must be rotated quarterly.
   5.3 Agent access must not exceed the least-privilege baseline of the invoking human.
DOC

cat > /tmp/kb-docs/access-certification-policy.txt << 'DOC'
IGA Policy: Access Certification

Policy ID: IGA-POL-002
Effective Date: 2026-01-01
Owner: Identity Governance Team

1. Purpose
   Access certification (also called access review or entitlement review) is the periodic
   process of verifying that user access is still appropriate and necessary.

2. Certification Frequency
   - Standard access: Annual certification required.
   - Privileged access (admin roles, financial write): Quarterly certification required.
   - Sensitive data access (PII, regulated data): Semi-annual certification required.
   - AI agent access: Quarterly certification required.

3. Certifier Responsibilities
   3.1 Direct managers certify employee access to standard applications.
   3.2 Application owners certify privileged access within their applications.
   3.3 The CISO certifies AI agent identity bindings and cross-account permissions.

4. Remediation
   4.1 Access not certified within 14 days of review open date is automatically revoked.
   4.2 Certification decisions must be logged with a reason code.
   4.3 Revoked access may be re-requested through the standard access request process.

5. AI Agent Certification
   5.1 Each AI agent identity binding (agent-to-model, agent-to-tool, agent-to-secret)
       must be included in quarterly certification.
   5.2 Dormant agents (no invocation in 90 days) must be deprovisioned or explicitly
       re-certified by the owning team.
DOC

cat > /tmp/kb-docs/privileged-access-policy.txt << 'DOC'
IGA Policy: Privileged Access Management

Policy ID: IGA-POL-003
Effective Date: 2026-01-01
Owner: Identity Governance Team

1. Definition
   Privileged access is any access that can modify security configurations, financial
   records, PII datasets, or the identity governance system itself.

2. Approval Requirements
   2.1 All privileged access requests require manager approval.
   2.2 Access to financial write systems additionally requires the data owner's approval.
   2.3 Emergency (break-glass) access requires CISO approval and is time-limited to 4 hours.

3. Authentication Requirements
   3.1 Privileged operations must be performed under a session with assurance level HIGH.
   3.2 MFA must be satisfied before any privileged operation is permitted.
   3.3 Session assurance level LOW is insufficient for privileged operations; the system
       must deny and log the attempt.

4. Logging and Monitoring
   4.1 All privileged access attempts (successful and denied) must be logged.
   4.2 Denied privileged access attempts must trigger a governance alert after 3 denials
       within a 24-hour period.
   4.3 AI agents invoking privileged tools must propagate the original caller's identity
       and session assurance level in the tool invocation log.

5. Violations
   5.1 Bypassing MFA or session assurance requirements is a critical policy violation.
   5.2 Repeated denied attempts will result in account suspension pending investigation.
DOC

aws s3 cp /tmp/kb-docs/least-privilege-policy.txt \
    "s3://${KB_BUCKET}/policies/least-privilege-policy.txt"
aws s3 cp /tmp/kb-docs/access-certification-policy.txt \
    "s3://${KB_BUCKET}/policies/access-certification-policy.txt"
aws s3 cp /tmp/kb-docs/privileged-access-policy.txt \
    "s3://${KB_BUCKET}/policies/privileged-access-policy.txt"

echo "Uploaded 3 policy documents to s3://${KB_BUCKET}/policies/"

# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 1, Step 3: Create IAM role for knowledge base ==="
# ---------------------------------------------------------------------------

cat > /tmp/kb-trust-policy.json << JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowBedrockKBAssumeRole",
      "Effect": "Allow",
      "Principal": { "Service": "bedrock.amazonaws.com" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "aws:SourceAccount": "${AWS_ACCOUNT_ID}" }
      }
    }
  ]
}
JSON

cat > /tmp/kb-permissions-policy.json << JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadKBDocumentsFromS3",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::${KB_BUCKET}",
        "arn:aws:s3:::${KB_BUCKET}/*"
      ]
    },
    {
      "Sid": "AllowBedrockEmbeddingModel",
      "Effect": "Allow",
      "Action": "bedrock:InvokeModel",
      "Resource": "arn:aws:bedrock:${AWS_REGION}::foundation-model/amazon.titan-embed-text-v1"
    }
  ]
}
JSON

if aws iam get-role --role-name "${KB_ROLE_NAME}" 2>/dev/null; then
    echo "Role ${KB_ROLE_NAME} already exists — skipping creation."
else
    aws iam create-role \
        --role-name "${KB_ROLE_NAME}" \
        --assume-role-policy-document file:///tmp/kb-trust-policy.json
    echo "Role created: ${KB_ROLE_NAME}"
fi

aws iam put-role-policy \
    --role-name "${KB_ROLE_NAME}" \
    --policy-name "${PROJECT_PREFIX}-kb-s3-policy" \
    --policy-document file:///tmp/kb-permissions-policy.json

export KB_ROLE_ARN="$(
    aws iam get-role \
        --role-name "${KB_ROLE_NAME}" \
        --query Role.Arn \
        --output text
)"
echo "KB role ARN: ${KB_ROLE_ARN}"

# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 1 complete. Phase 2: Create KB via console ==="
echo ""
echo "Open the Bedrock console → Knowledge Bases → Create knowledge base:"
echo ""
echo "  Name:              ${PROJECT_PREFIX}-policy-kb"
echo "  IAM role:          ${KB_ROLE_ARN}"
echo "  Embedding model:   Titan Text Embeddings v1 (amazon.titan-embed-text-v1)"
echo "  Vector store:      Quick create (Bedrock manages OpenSearch Serverless)"
echo ""
echo "  Data source:"
echo "    Type:            Amazon S3"
echo "    Bucket URI:      s3://${KB_BUCKET}/policies/"
echo "    Chunking:        Default (fixed-size, 300 tokens, 20% overlap)"
echo ""
echo "Record the KB_ID from the console and export it:"
echo "  export KB_ID=<knowledge-base-id-from-console>"
echo "  export KB_DATA_SOURCE_ID=<data-source-id-from-console>"
echo ""
echo "Then run Phase 3:"
echo "  bash setup/create_kb.sh --phase3"
# ---------------------------------------------------------------------------

if [ "${1:-}" = "--phase3" ]; then

    if [ -z "${KB_ID:-}" ]; then
        echo "ERROR: KB_ID must be set before running Phase 3."
        echo "  export KB_ID=<knowledge-base-id>"
        exit 1
    fi
    if [ -z "${KB_DATA_SOURCE_ID:-}" ]; then
        echo "ERROR: KB_DATA_SOURCE_ID must be set before running Phase 3."
        echo "  export KB_DATA_SOURCE_ID=<data-source-id>"
        exit 1
    fi
    if [ -z "${ACCESS_INVENTORY_AGENT_ID:-}" ]; then
        echo "ERROR: ACCESS_INVENTORY_AGENT_ID must be set. Agents must exist before attachment."
        exit 1
    fi

    echo ""
    echo "=== Phase 3, Step 1: Start KB ingestion job ==="

    INGESTION_JOB_ID="$(
        aws bedrock-agent start-ingestion-job \
            --knowledge-base-id "${KB_ID}" \
            --data-source-id "${KB_DATA_SOURCE_ID}" \
            --region "${AWS_REGION}" \
            --query ingestionJob.ingestionJobId \
            --output text
    )"
    echo "Ingestion job started: ${INGESTION_JOB_ID}"
    echo "Monitor: aws bedrock-agent get-ingestion-job --knowledge-base-id ${KB_ID} --data-source-id ${KB_DATA_SOURCE_ID} --ingestion-job-id ${INGESTION_JOB_ID} --region ${AWS_REGION}"

    echo ""
    echo "=== Phase 3, Step 2: Attach KB to PolicyExplanationAgent ==="
    echo ""
    echo "Attach via console (recommended):"
    echo "  Bedrock console → Agents → PolicyExplanationAgent → Edit"
    echo "  → Knowledge Bases → Add → select ${PROJECT_PREFIX}-policy-kb"
    echo "  → Prepare agent → Update alias"
    echo ""
    echo "Attach via CLI:"
    echo "  aws bedrock-agent associate-agent-knowledge-base \\"
    echo "    --agent-id \"\${POLICY_EXPLANATION_AGENT_ID}\" \\"
    echo "    --agent-version DRAFT \\"
    echo "    --knowledge-base-id \"${KB_ID}\" \\"
    echo "    --knowledge-base-state ENABLED \\"
    echo "    --region \"\${AWS_REGION}\""
    echo ""
    echo "  Then prepare and update alias:"
    echo "  aws bedrock-agent prepare-agent --agent-id \"\${POLICY_EXPLANATION_AGENT_ID}\" --region \"\${AWS_REGION}\""
    echo ""
    echo "Verify attachment:"
    echo "  aws bedrock-agent list-agent-knowledge-bases \\"
    echo "    --agent-id \"\${POLICY_EXPLANATION_AGENT_ID}\" \\"
    echo "    --agent-version DRAFT \\"
    echo "    --region \"\${AWS_REGION}\""
    echo ""
    echo "Test KB retrieval (after agent is prepared and alias updated):"
    echo "  python client/direct_invoke_agent.py \\"
    echo "    --region \"\${AWS_REGION}\" \\"
    echo "    --agent-id \"\${SUPERVISOR_AGENT_ID}\" \\"
    echo "    --agent-alias-id \"\${SUPERVISOR_AGENT_ALIAS_ID}\" \\"
    echo "    --message \"What is the least privilege policy for Salesforce access?\""
    echo "  Expected: trace shows knowledge_base trace with records_retrieved > 0"

fi

export KB_BUCKET
echo ""
echo "KB bucket: s3://${KB_BUCKET}"