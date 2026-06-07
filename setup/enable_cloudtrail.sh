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
# Lambda Invoke is the only data event useful here.
# InvokeAgent and GetSecretValue are MANAGEMENT events — captured by the
# trail automatically without any selector. No Bedrock resource types are
# valid advanced event selector data event types.

aws cloudtrail put-event-selectors \
    --trail-name "${TRAIL_NAME}" \
    --region "${AWS_REGION}" \
    --advanced-event-selectors '[
        {
            "Name": "LambdaInvoke",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]}
            ]
        }
    ]'

echo ""
echo "=== CloudTrail setup complete ==="
echo "Trail:        ${TRAIL_NAME}"
echo "Bucket:       s3://${TRAIL_BUCKET}"
echo ""
echo "Data event selector active:"
echo "  Lambda Invoke    → explicit data event (Bedrock → tool Lambda call)"
echo ""
echo "Management events captured by default (no selector needed):"
echo "  InvokeAgent      → who invoked which agent alias (bedrock-agent-runtime)"
echo "  GetSecretValue   → credential access for api_key path (secretsmanager)"
echo "  CreateAgent, CreateGuardrail, etc. → control-plane changes"
echo ""
echo "KB and guardrail evidence: Bedrock model invocation logs + front door Lambda trace."
echo ""
echo "Note: Lambda data events are high-volume in active accounts."
echo "Scope Lambda selectors to the tool handler ARN in production:"
echo "  aws cloudtrail put-event-selectors ... with resources.ARN filter"
echo ""
echo "Verify trail is logging:"
echo "  aws cloudtrail get-trail-status --name ${TRAIL_NAME} --region ${AWS_REGION}"