#!/usr/bin/env bash
# setup/enable_cloudtrail.sh
#
# Evidence stream 1 of 3: CloudTrail data events.
# Creates a trail with data event selectors for Bedrock, Lambda, and Secrets Manager.
# Covers v3 event_types: agent_invocation, authentication (partial), resource_access (partial).
#
# Prerequisites: AWS_REGION, AWS_ACCOUNT_ID, PROJECT_PREFIX set in environment.
# Run once before executing any tutorial flows.

set -euo pipefail

TRAIL_BUCKET="${PROJECT_PREFIX}-${AWS_ACCOUNT_ID}-${AWS_REGION}-trail"
TRAIL_NAME="${PROJECT_PREFIX}-governance-trail"

echo "=== Step 1: Create CloudTrail S3 bucket ==="

if aws s3api head-bucket --bucket "${TRAIL_BUCKET}" --region "${AWS_REGION}" 2>/dev/null; then
    echo "Bucket ${TRAIL_BUCKET} already exists — skipping."
else
    if [ "${AWS_REGION}" = "us-east-1" ]; then
        aws s3api create-bucket \
            --bucket "${TRAIL_BUCKET}" \
            --region "${AWS_REGION}"
    else
        aws s3api create-bucket \
            --bucket "${TRAIL_BUCKET}" \
            --region "${AWS_REGION}" \
            --create-bucket-configuration "LocationConstraint=${AWS_REGION}"
    fi
    echo "Created: ${TRAIL_BUCKET}"
fi

aws s3api put-public-access-block \
    --bucket "${TRAIL_BUCKET}" \
    --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo ""
echo "=== Step 2: Apply CloudTrail bucket policy ==="

cat > /tmp/cloudtrail-bucket-policy.json << JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${TRAIL_BUCKET}"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${TRAIL_BUCKET}/AWSLogs/${AWS_ACCOUNT_ID}/*",
      "Condition": {
        "StringEquals": { "s3:x-amz-acl": "bucket-owner-full-control" }
      }
    }
  ]
}
JSON

aws s3api put-bucket-policy \
    --bucket "${TRAIL_BUCKET}" \
    --policy file:///tmp/cloudtrail-bucket-policy.json

echo "Bucket policy applied."

echo ""
echo "=== Step 3: Create trail and start logging ==="

if aws cloudtrail get-trail \
        --name "${TRAIL_NAME}" \
        --region "${AWS_REGION}" 2>/dev/null; then
    echo "Trail ${TRAIL_NAME} already exists — skipping creation."
else
    aws cloudtrail create-trail \
        --name "${TRAIL_NAME}" \
        --s3-bucket-name "${TRAIL_BUCKET}" \
        --is-multi-region-trail \
        --enable-log-file-validation \
        --region "${AWS_REGION}"

    aws cloudtrail start-logging \
        --name "${TRAIL_NAME}" \
        --region "${AWS_REGION}"

    echo "Trail created and logging started: ${TRAIL_NAME}"
fi

echo ""
echo "=== Step 4: Enable data event selectors ==="
# Bedrock::AgentAlias   — InvokeAgent        → v3 agent_invocation
# Bedrock::KnowledgeBase— Retrieve           → corroborates knowledge_base_query
# Bedrock::Guardrail    — ApplyGuardrail     → corroborates guardrail_evaluation
# Lambda::Function      — Invoke             → links Bedrock → tool Lambda call chain
# SecretsManager::Secret— GetSecretValue     → v3 resource_access for api_key credential path

aws cloudtrail put-event-selectors \
    --trail-name "${TRAIL_NAME}" \
    --region "${AWS_REGION}" \
    --advanced-event-selectors '[
        {
            "Name": "BedrockAgentAlias",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::Bedrock::AgentAlias"]}
            ]
        },
        {
            "Name": "BedrockKnowledgeBase",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::Bedrock::KnowledgeBase"]}
            ]
        },
        {
            "Name": "BedrockGuardrail",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::Bedrock::Guardrail"]}
            ]
        },
        {
            "Name": "LambdaInvoke",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]}
            ]
        },
        {
            "Name": "SecretsManagerGetSecretValue",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::SecretsManager::Secret"]}
            ]
        }
    ]'

echo ""
echo "=== CloudTrail setup complete ==="
echo "Trail:        ${TRAIL_NAME}"
echo "Bucket:       s3://${TRAIL_BUCKET}"
echo ""
echo "Events captured:"
echo "  InvokeAgent (AgentAlias)         → v3 agent_invocation"
echo "  Retrieve (KnowledgeBase)          → corroborates knowledge_base_query"
echo "  ApplyGuardrail (Guardrail)        → corroborates guardrail_evaluation"
echo "  Invoke (Lambda)                   → tool Lambda call chain linkage"
echo "  GetSecretValue (SecretsManager)   → v3 resource_access for api_key path"
echo ""
echo "Note: Lambda data events are high-volume in active accounts."
echo "Scope Lambda selectors to the tool handler ARN in production:"
echo "  aws cloudtrail put-event-selectors ... with resources.ARN filter"
echo ""
echo "Verify trail is logging:"
echo "  aws cloudtrail get-trail-status --name ${TRAIL_NAME} --region ${AWS_REGION}"