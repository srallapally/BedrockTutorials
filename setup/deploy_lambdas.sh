#!/usr/bin/env bash
# setup/deploy_lambdas.sh
#
# Creates dedicated CloudWatch log groups and deploys both tutorial Lambdas
# with --logging-config so their output lands in the governance log groups
# rather than the default /aws/lambda/{name} groups.
#
# Log group routing:
#   lambda_tool_handler.py  → /agent-governance/tool-runtime
#   frontdoor_handler.py    → /agent-governance/agent-gateway
#
# Prerequisites:
#   AWS_REGION, AWS_ACCOUNT_ID, PROJECT_PREFIX set in environment.
#   For tool Lambda: MOCK_API_KEY_SECRET_ARN, TOOL_LAMBDA_ROLE_ARN
#   For front door Lambda: SUPERVISOR_AGENT_ID, SUPERVISOR_AGENT_ALIAS_ID,
#                          FRONTDOOR_ROLE_ARN
#   Optional: ALLOWED_PRINCIPALS (comma-separated IAM ARNs; empty = allow all)
#             WORKLOAD_IDENTITY_NAME, OAUTH_PROVIDER_NAME, OAUTH_SCOPES,
#             OAUTH_CALLBACK_URL, OAUTH_IDP_PROVIDER, USE_MOCK_OAUTH

set -euo pipefail

TOOL_LOG_GROUP="/agent-governance/tool-runtime"
GATEWAY_LOG_GROUP="/agent-governance/agent-gateway"

# ---------------------------------------------------------------------------
echo "=== Step 1: Create dedicated governance log groups ==="
# ---------------------------------------------------------------------------

for LOG_GROUP in "${TOOL_LOG_GROUP}" "${GATEWAY_LOG_GROUP}"; do
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

    aws logs put-retention-policy \
        --log-group-name "${LOG_GROUP}" \
        --retention-in-days 90 \
        --region "${AWS_REGION}"
done

echo "Retention set to 90 days on both log groups."

# ---------------------------------------------------------------------------
echo ""
echo "=== Step 2: Build and deploy tool Lambda ==="
# lambda_tool_handler.py → /agent-governance/tool-runtime
# ---------------------------------------------------------------------------

mkdir -p build
cp lambda_tool_handler.py build/
cd build
zip -q function.zip lambda_tool_handler.py
cd ..

TOOL_FUNCTION_NAME="${PROJECT_PREFIX}-tool-handler"

if aws lambda get-function \
        --function-name "${TOOL_FUNCTION_NAME}" \
        --region "${AWS_REGION}" 2>/dev/null; then

    echo "Function ${TOOL_FUNCTION_NAME} exists — updating code and configuration."

    aws lambda update-function-code \
        --function-name "${TOOL_FUNCTION_NAME}" \
        --zip-file fileb://build/function.zip \
        --region "${AWS_REGION}"

    aws lambda wait function-updated \
        --function-name "${TOOL_FUNCTION_NAME}" \
        --region "${AWS_REGION}"

    aws lambda update-function-configuration \
        --function-name "${TOOL_FUNCTION_NAME}" \
        --timeout 30 \
        --logging-config "LogGroup=${TOOL_LOG_GROUP},LogFormat=JSON" \
        --environment "Variables={
            MOCK_API_KEY_SECRET_ARN=${MOCK_API_KEY_SECRET_ARN},
            DEFAULT_CREDENTIAL_TYPE=iam_role,
            AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID},
            WORKLOAD_IDENTITY_NAME=${WORKLOAD_IDENTITY_NAME:-iga-bedrock-agent-3lo-workload},
            OAUTH_PROVIDER_NAME=${OAUTH_PROVIDER_NAME:-google-provider},
            OAUTH_SCOPES=${OAUTH_SCOPES:-https://www.googleapis.com/auth/drive.metadata.readonly},
            OAUTH_CALLBACK_URL=${OAUTH_CALLBACK_URL:-},
            OAUTH_IDP_PROVIDER=${OAUTH_IDP_PROVIDER:-google},
            USE_MOCK_OAUTH=${USE_MOCK_OAUTH:-false}
        }" \
        --region "${AWS_REGION}"

else

    aws lambda create-function \
        --function-name "${TOOL_FUNCTION_NAME}" \
        --runtime python3.12 \
        --role "${TOOL_LAMBDA_ROLE_ARN}" \
        --handler lambda_tool_handler.lambda_handler \
        --zip-file fileb://build/function.zip \
        --timeout 30 \
        --logging-config "LogGroup=${TOOL_LOG_GROUP},LogFormat=JSON" \
        --environment "Variables={
            MOCK_API_KEY_SECRET_ARN=${MOCK_API_KEY_SECRET_ARN},
            DEFAULT_CREDENTIAL_TYPE=iam_role,
            AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID},
            WORKLOAD_IDENTITY_NAME=${WORKLOAD_IDENTITY_NAME:-iga-bedrock-agent-3lo-workload},
            OAUTH_PROVIDER_NAME=${OAUTH_PROVIDER_NAME:-google-provider},
            OAUTH_SCOPES=${OAUTH_SCOPES:-https://www.googleapis.com/auth/drive.metadata.readonly},
            OAUTH_CALLBACK_URL=${OAUTH_CALLBACK_URL:-},
            OAUTH_IDP_PROVIDER=${OAUTH_IDP_PROVIDER:-google},
            USE_MOCK_OAUTH=${USE_MOCK_OAUTH:-false}
        }" \
        --region "${AWS_REGION}"

fi

export TOOL_LAMBDA_ARN="$(
    aws lambda get-function \
        --function-name "${TOOL_FUNCTION_NAME}" \
        --region "${AWS_REGION}" \
        --query Configuration.FunctionArn \
        --output text
)"
echo "Tool Lambda ARN: ${TOOL_LAMBDA_ARN}"

# Allow Bedrock to invoke the tool Lambda
aws lambda add-permission \
    --function-name "${TOOL_FUNCTION_NAME}" \
    --statement-id "AllowBedrockInvoke" \
    --action "lambda:InvokeFunction" \
    --principal "bedrock.amazonaws.com" \
    --source-account "${AWS_ACCOUNT_ID}" \
    --region "${AWS_REGION}" 2>/dev/null || echo "Bedrock invoke permission already exists."

# ---------------------------------------------------------------------------
echo ""
echo "=== Step 3: Build and deploy front door Lambda ==="
# frontdoor_handler.py → /agent-governance/agent-gateway
# ---------------------------------------------------------------------------

mkdir -p frontdoor-build
cp frontdoor_handler.py frontdoor-build/
cd frontdoor-build
zip -q frontdoor.zip frontdoor_handler.py
cd ..

FRONTDOOR_FUNCTION_NAME="${PROJECT_PREFIX}-frontdoor"

if aws lambda get-function \
        --function-name "${FRONTDOOR_FUNCTION_NAME}" \
        --region "${AWS_REGION}" 2>/dev/null; then

    echo "Function ${FRONTDOOR_FUNCTION_NAME} exists — updating code and configuration."

    aws lambda update-function-code \
        --function-name "${FRONTDOOR_FUNCTION_NAME}" \
        --zip-file fileb://frontdoor-build/frontdoor.zip \
        --region "${AWS_REGION}"

    aws lambda wait function-updated \
        --function-name "${FRONTDOOR_FUNCTION_NAME}" \
        --region "${AWS_REGION}"

    aws lambda update-function-configuration \
        --function-name "${FRONTDOOR_FUNCTION_NAME}" \
        --timeout 60 \
        --logging-config "LogGroup=${GATEWAY_LOG_GROUP},LogFormat=JSON" \
        --environment "Variables={
            AGENT_ID=${SUPERVISOR_AGENT_ID},
            AGENT_ALIAS_ID=${SUPERVISOR_AGENT_ALIAS_ID},
            ALLOWED_PRINCIPALS=${ALLOWED_PRINCIPALS:-}
        }" \
        --region "${AWS_REGION}"

else

    aws lambda create-function \
        --function-name "${FRONTDOOR_FUNCTION_NAME}" \
        --runtime python3.12 \
        --role "${FRONTDOOR_ROLE_ARN}" \
        --handler frontdoor_handler.lambda_handler \
        --zip-file fileb://frontdoor-build/frontdoor.zip \
        --timeout 60 \
        --logging-config "LogGroup=${GATEWAY_LOG_GROUP},LogFormat=JSON" \
        --environment "Variables={
            AGENT_ID=${SUPERVISOR_AGENT_ID},
            AGENT_ALIAS_ID=${SUPERVISOR_AGENT_ALIAS_ID},
            ALLOWED_PRINCIPALS=${ALLOWED_PRINCIPALS:-}
        }" \
        --region "${AWS_REGION}"

fi

export FRONTDOOR_LAMBDA_ARN="$(
    aws lambda get-function \
        --function-name "${FRONTDOOR_FUNCTION_NAME}" \
        --region "${AWS_REGION}" \
        --query Configuration.FunctionArn \
        --output text
)"
echo "Front door Lambda ARN: ${FRONTDOOR_LAMBDA_ARN}"

# ---------------------------------------------------------------------------
echo ""
echo "=== Deployment complete ==="
echo ""
echo "Tool Lambda:      ${TOOL_LAMBDA_ARN}"
echo "  Log group:      ${TOOL_LOG_GROUP}"
echo ""
echo "Front door Lambda:${FRONTDOOR_LAMBDA_ARN}"
echo "  Log group:      ${GATEWAY_LOG_GROUP}"
echo ""
echo "CloudWatch Insights — verify tool activity:"
echo "  aws logs start-query \\"
echo "    --log-group-name ${TOOL_LOG_GROUP} \\"
echo "    --start-time \$(date -d '1 hour ago' +%s) \\"
echo "    --end-time \$(date +%s) \\"
echo "    --query-string 'fields @timestamp, event_type, credential_type, policy_decision, success | filter event_type = \"bedrock_tool_activity\" | sort @timestamp desc | limit 20' \\"
echo "    --region \${AWS_REGION}"
echo ""
echo "CloudWatch Insights — verify gateway activity:"
echo "  aws logs start-query \\"
echo "    --log-group-name ${GATEWAY_LOG_GROUP} \\"
echo "    --start-time \$(date -d '1 hour ago' +%s) \\"
echo "    --end-time \$(date +%s) \\"
echo "    --query-string 'fields @timestamp, event_type, invocation_phase, session_assurance_level, authorized | sort @timestamp desc | limit 20' \\"
echo "    --region \${AWS_REGION}"