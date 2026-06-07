#!/usr/bin/env bash
# setup/enable_model_invocation_logging.sh
#
# Evidence stream 2 of 3: Bedrock model invocation logs.
# Enables metadata-only logging to CloudWatch — no raw prompts or responses.
# Covers v3 event_types: guardrail_evaluation, knowledge_base_query.
#
# Prerequisites: AWS_REGION, AWS_ACCOUNT_ID, PROJECT_PREFIX set in environment.
# Run once, after the log group and IAM role are created below.
#
# Note: this is an account-level + region-level setting. It applies to all
# Bedrock model invocations in this region, not just the tutorial agents.

set -euo pipefail

LOG_GROUP="/aws/bedrock/model-invocations"
LOGGING_ROLE_NAME="${PROJECT_PREFIX}-bedrock-logging-role"

echo "=== Step 1: Create CloudWatch log group ==="

if aws logs describe-log-groups \
        --log-group-name-prefix "${LOG_GROUP}" \
        --region "${AWS_REGION}" \
        --query "logGroups[?logGroupName=='${LOG_GROUP}']" \
        --output text | grep -q "${LOG_GROUP}"; then
    echo "Log group ${LOG_GROUP} already exists — skipping."
else
    aws logs create-log-group \
        --log-group-name "${LOG_GROUP}" \
        --region "${AWS_REGION}"
    echo "Created: ${LOG_GROUP}"
fi

# Set 90-day retention on model invocation logs
aws logs put-retention-policy \
    --log-group-name "${LOG_GROUP}" \
    --retention-in-days 90 \
    --region "${AWS_REGION}"
echo "Retention set to 90 days."

echo ""
echo "=== Step 2: Create IAM role for Bedrock logging ==="

cat > /tmp/bedrock-logging-trust.json << JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowBedrockAssumeRole",
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

cat > /tmp/bedrock-logging-policy.json << JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowBedrockWriteModelInvocationLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:${AWS_REGION}:${AWS_ACCOUNT_ID}:log-group:${LOG_GROUP}:*"
    }
  ]
}
JSON

if aws iam get-role \
        --role-name "${LOGGING_ROLE_NAME}" 2>/dev/null; then
    echo "Role ${LOGGING_ROLE_NAME} already exists — skipping creation."
else
    aws iam create-role \
        --role-name "${LOGGING_ROLE_NAME}" \
        --assume-role-policy-document file:///tmp/bedrock-logging-trust.json
    echo "Role created: ${LOGGING_ROLE_NAME}"
fi

aws iam put-role-policy \
    --role-name "${LOGGING_ROLE_NAME}" \
    --policy-name "${PROJECT_PREFIX}-bedrock-logging-policy" \
    --policy-document file:///tmp/bedrock-logging-policy.json
echo "Permissions policy applied."

export BEDROCK_LOGGING_ROLE_ARN="$(
    aws iam get-role \
        --role-name "${LOGGING_ROLE_NAME}" \
        --query Role.Arn \
        --output text
)"
echo "Role ARN: ${BEDROCK_LOGGING_ROLE_ARN}"

echo ""
echo "=== Step 3: Enable model invocation logging (metadata only) ==="
# textDataDeliveryEnabled=false  — prompts and responses are NOT logged.
# imageDataDeliveryEnabled=false — image content is NOT logged.
# embeddingDataDeliveryEnabled=false — embeddings are NOT logged.
# Only invocation metadata (model ID, latency, token counts, guardrail actions,
# knowledge base retrieval counts) is written to CloudWatch.

aws bedrock put-model-invocation-logging-configuration \
    --region "${AWS_REGION}" \
    --logging-config "{
        \"cloudWatchConfig\": {
            \"logGroupName\": \"${LOG_GROUP}\",
            \"roleArn\": \"${BEDROCK_LOGGING_ROLE_ARN}\"
        },
        \"textDataDeliveryEnabled\": false,
        \"imageDataDeliveryEnabled\": false,
        \"embeddingDataDeliveryEnabled\": false
    }"

echo ""
echo "=== Model invocation logging setup complete ==="
echo "Log group:    ${LOG_GROUP}"
echo "Logging role: ${BEDROCK_LOGGING_ROLE_ARN}"
echo ""
echo "Metadata logged per invocation:"
echo "  - Model ID, agent ID, session ID"
echo "  - Input/output token counts"
echo "  - Guardrail action and assessment metadata"
echo "  - Knowledge base retrieval counts"
echo "  - Latency"
echo ""
echo "NOT logged (textDataDeliveryEnabled=false):"
echo "  - Raw prompt text"
echo "  - Raw model response text"
echo ""
echo "Verify logging is active:"
echo "  aws bedrock get-model-invocation-logging-configuration --region ${AWS_REGION}"