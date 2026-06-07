# bedrock-agent-tools/lambda_tool_handler.py
import json
import os
import time
import urllib.request
import boto3

secrets = boto3.client("secretsmanager")

MOCK_API_KEY_SECRET_ARN = os.environ.get("MOCK_API_KEY_SECRET_ARN", "")
MOCK_MCP_URL = os.environ.get("MOCK_MCP_URL", "")
DEFAULT_CREDENTIAL_TYPE = os.environ.get("DEFAULT_CREDENTIAL_TYPE", "iam_role")

# AgentCore Identity config for 3LO
WORKLOAD_IDENTITY_NAME = os.environ.get("WORKLOAD_IDENTITY_NAME", "iga-bedrock-agent-3lo-workload")
OAUTH_PROVIDER_NAME = os.environ.get("OAUTH_PROVIDER_NAME", "google-provider")
OAUTH_SCOPES = os.environ.get("OAUTH_SCOPES", "https://www.googleapis.com/auth/drive.metadata.readonly")
OAUTH_CALLBACK_URL = os.environ.get("OAUTH_CALLBACK_URL", "https://9hqdv5gcka.execute-api.us-east-1.amazonaws.com/oauth/callback")
OAUTH_IDP_PROVIDER = os.environ.get("OAUTH_IDP_PROVIDER", "google")

_AUTH_PROTOCOL = {
    "api_key": "API_KEY",
    "iam_role": "IAM_SigV4",
    "oauth_2lo": "OAuth2.0",
    "mock_oauth_obo": "OAuth2.0",
    "oauth_3lo": "OAuth2.0",
}

_IDP_PROVIDER = {
    "api_key": None,
    "iam_role": "aws_iam",
}


def _get_idp_provider(credential_type):
    if credential_type in _IDP_PROVIDER:
        return _IDP_PROVIDER[credential_type]
    if credential_type in ("oauth_2lo", "mock_oauth_obo", "oauth_3lo"):
        return OAUTH_IDP_PROVIDER
    return None


def get_parameter(event, name):
    for param in event.get("parameters", []) or []:
        if param.get("name") == name:
            return param.get("value")
    content = event.get("requestBody", {}).get("content", {})
    for media_type in content.values():
        for prop in media_type.get("properties", []) or []:
            if prop.get("name") == name:
                return prop.get("value")
    return None


def get_secret(secret_arn):
    response = secrets.get_secret_value(SecretId=secret_arn)
    return response["SecretString"]


def get_3lo_token(user_identity):
    """
    Call AgentCore Identity to get a user-delegated OAuth token.
    Returns {"access_token": "..."} if token is in vault,
    or {"authorization_required": true, "authorization_url": "..."} if consent needed.
    """
    client = boto3.client("bedrock-agentcore", region_name=os.environ.get("AWS_REGION", "us-east-1"))

    # Step 1: Get workload access token for this user
    print(json.dumps({"_debug_3lo": "step1_start", "workloadName": WORKLOAD_IDENTITY_NAME, "userId": user_identity}))
    wat_resp = client.get_workload_access_token_for_user_id(
        workloadName=WORKLOAD_IDENTITY_NAME,
        userId=user_identity
    )
    workload_token = wat_resp["workloadAccessToken"]
    print(json.dumps({"_debug_3lo": "step1_ok", "token_prefix": workload_token[:20]}))

    # Step 2: Request the OAuth2 resource token
    scopes = [s.strip() for s in OAUTH_SCOPES.split(",")]
    return_url = f"{OAUTH_CALLBACK_URL}?user_id={urllib.request.quote(user_identity)}"
    print(json.dumps({"_debug_3lo": "step2_start", "provider": OAUTH_PROVIDER_NAME, "scopes": scopes, "returnUrl": return_url}))
    token_resp = client.get_resource_oauth2_token(
        workloadIdentityToken=workload_token,
        resourceCredentialProviderName=OAUTH_PROVIDER_NAME,
        scopes=scopes,
        oauth2Flow="USER_FEDERATION",
        resourceOauth2ReturnUrl=return_url,
        forceAuthentication=False
    )
    print(json.dumps({"_debug_3lo": "step2_ok", "hasAccessToken": bool(token_resp.get("accessToken")), "hasAuthUrl": bool(token_resp.get("authorizationUrl"))}))

    access_token = token_resp.get("accessToken")
    if access_token:
        return {"access_token": access_token}

    authorization_url = token_resp.get("authorizationUrl", "")
    session_uri = token_resp.get("sessionUri", "")

    callback_with_params = (
        f"{OAUTH_CALLBACK_URL}?user_id={urllib.request.quote(user_identity)}"
        f"&session_uri={urllib.request.quote(session_uri)}"
    )

    return {
        "authorization_required": True,
        "authorization_url": authorization_url,
        "callback_url": callback_with_params,
        "session_uri": session_uri
    }


def log_activity(
    *,
    request_id,
    user_identity,
    agent_id,
    sub_agent_name,
    tool_name,
    mcp_server,
    credential_type,
    auth_protocol,
    idp_provider,
    success,
    latency_ms,
    sanitized_arguments,
    error_type=None
):
    payload = {
        "event_type": "bedrock_tool_activity",
        "request_id": request_id,
        "user_identity": user_identity,
        "agent_id": agent_id,
        "sub_agent_name": sub_agent_name,
        "tool_name": tool_name,
        "mcp_server": mcp_server,
        "credential_type": credential_type,
        "auth_protocol": auth_protocol,
        "idp_provider": idp_provider,
        "success": success,
        "latency_ms": latency_ms,
        "sanitized_arguments": sanitized_arguments,
    }
    if error_type:
        payload["error_type"] = error_type

    print(json.dumps(payload))


def bedrock_response(event, body, status_code=200):
    return {
        "messageVersion": event.get("messageVersion", "1.0"),
        "response": {
            "actionGroup": event["actionGroup"],
            "apiPath": event.get("apiPath", "/unknown"),
            "httpMethod": event.get("httpMethod", "POST"),
            "httpStatusCode": status_code,
            "responseBody": {
                "application/json": {
                    "body": json.dumps(body)
                }
            }
        },
        "sessionAttributes": event.get("sessionAttributes", {}),
        "promptSessionAttributes": event.get("promptSessionAttributes", {})
    }


def call_mock_mcp_tool(tool_name, arguments, credential_type, user_identity):
    headers = {
        "Content-Type": "application/json"
    }

    if credential_type == "api_key":
        headers["x-api-key"] = get_secret(MOCK_API_KEY_SECRET_ARN)
    elif credential_type == "mock_oauth_obo":
        headers["Authorization"] = "Bearer mock-user-delegated-token"
    elif credential_type == "oauth_2lo":
        headers["Authorization"] = "Bearer mock-agent-owned-token"
    elif credential_type == "oauth_3lo":
        result = get_3lo_token(user_identity)
        if result.get("authorization_required"):
            return result
        headers["Authorization"] = f"Bearer {result['access_token']}"

    if not MOCK_MCP_URL:
        return {
            "mock": True,
            "tool_name": tool_name,
            "arguments": arguments,
            "result": {
                "accounts": [
                    {"application": "Salesforce", "account": "sf-" + arguments.get("user_email", "unknown")},
                    {"application": "Workday", "account": "wd-" + arguments.get("user_email", "unknown")}
                ],
                "entitlements": [
                    "Salesforce:Reports:Read",
                    "Workday:Worker:Read"
                ]
            }
        }

    request_body = json.dumps({
        "tool_name": tool_name,
        "arguments": arguments
    }).encode("utf-8")

    req = urllib.request.Request(
        MOCK_MCP_URL,
        data=request_body,
        headers=headers,
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def lambda_handler(event, context):
    start = time.time()

    session_attributes = event.get("sessionAttributes", {}) or {}
    request_id = session_attributes.get("request_id", context.aws_request_id)
    user_identity = session_attributes.get("user_identity", "unknown")

    agent_info = event.get("agent", {}) or {}
    agent_id = agent_info.get("id", "unknown")
    sub_agent_name = agent_info.get("name", "unknown")

    api_path = event.get("apiPath", "")
    tool_name = api_path if api_path else "unknown_tool"

    user_email = get_parameter(event, "user_email") or "unknown@example.com"

    credential_type = session_attributes.get("credential_type", DEFAULT_CREDENTIAL_TYPE)

    auth_protocol = _AUTH_PROTOCOL.get(credential_type)
    idp_provider = _get_idp_provider(credential_type)

    sanitized_arguments = {
        "user_email_domain": user_email.split("@")[-1] if "@" in user_email else "unknown"
    }

    try:
        tool_result = call_mock_mcp_tool(
            tool_name=tool_name,
            arguments={"user_email": user_email},
            credential_type=credential_type,
            user_identity=user_identity
        )

        if tool_result.get("authorization_required"):
            latency_ms = int((time.time() - start) * 1000)
            log_activity(
                request_id=request_id,
                user_identity=user_identity,
                agent_id=agent_id,
                sub_agent_name=sub_agent_name,
                tool_name=tool_name,
                mcp_server="mock-access-mcp",
                credential_type=credential_type,
                auth_protocol=auth_protocol,
                idp_provider=idp_provider,
                success=False,
                latency_ms=latency_ms,
                sanitized_arguments=sanitized_arguments,
                error_type="authorization_required"
            )
            return bedrock_response(event, tool_result, 200)

        latency_ms = int((time.time() - start) * 1000)

        log_activity(
            request_id=request_id,
            user_identity=user_identity,
            agent_id=agent_id,
            sub_agent_name=sub_agent_name,
            tool_name=tool_name,
            mcp_server="mock-access-mcp",
            credential_type=credential_type,
            auth_protocol=auth_protocol,
            idp_provider=idp_provider,
            success=True,
            latency_ms=latency_ms,
            sanitized_arguments=sanitized_arguments
        )

        return bedrock_response(event, tool_result, 200)

    except Exception as exc:
        latency_ms = int((time.time() - start) * 1000)

        log_activity(
            request_id=request_id,
            user_identity=user_identity,
            agent_id=agent_id,
            sub_agent_name=sub_agent_name,
            tool_name=tool_name,
            mcp_server="mock-access-mcp",
            credential_type=credential_type,
            auth_protocol=auth_protocol,
            idp_provider=idp_provider,
            success=False,
            latency_ms=latency_ms,
            sanitized_arguments=sanitized_arguments,
            error_type=type(exc).__name__
        )

        return bedrock_response(
            event,
            {"error": "tool invocation failed", "error_type": type(exc).__name__},
            500
        )