# bedrock-agent-tools/lambda_tool_handler.py
import json
import os
import time
import urllib.parse
import urllib.request

import boto3

secrets = boto3.client("secretsmanager")

MOCK_API_KEY_SECRET_ARN  = os.environ.get("MOCK_API_KEY_SECRET_ARN", "")
MOCK_MCP_URL             = os.environ.get("MOCK_MCP_URL", "")
DEFAULT_CREDENTIAL_TYPE  = os.environ.get("DEFAULT_CREDENTIAL_TYPE", "iam_role")
AWS_ACCOUNT_ID           = os.environ.get("AWS_ACCOUNT_ID", "")
# USE_MOCK_OAUTH=true → Chunk 10A mock OBO path; unset/false → real AgentCore Identity 3LO
USE_MOCK_OAUTH           = os.environ.get("USE_MOCK_OAUTH", "false").lower() == "true"

# AgentCore Identity config for delegated OAuth (3LO)
WORKLOAD_IDENTITY_NAME = os.environ.get("WORKLOAD_IDENTITY_NAME", "iga-bedrock-agent-3lo-workload")
OAUTH_PROVIDER_NAME    = os.environ.get("OAUTH_PROVIDER_NAME", "google-provider")
OAUTH_SCOPES           = os.environ.get("OAUTH_SCOPES", "https://www.googleapis.com/auth/drive.metadata.readonly")
OAUTH_CALLBACK_URL     = os.environ.get("OAUTH_CALLBACK_URL", "")
OAUTH_IDP_PROVIDER     = os.environ.get("OAUTH_IDP_PROVIDER", "google")

# ---------------------------------------------------------------------------
# Credential type lookup tables
# ---------------------------------------------------------------------------

_AUTH_PROTOCOL = {
    "api_key":           "API_KEY",
    "iam_role":          "IAM_SigV4",
    "service_principal": "OAuth2.0",   # renamed from oauth_2lo
    "delegated_oauth":   "OAuth2.0",   # renamed from oauth_3lo / mock_oauth_obo
}

_IDP_PROVIDER_MAP = {
    "api_key":  None,
    "iam_role": "aws_iam",
}

# v3 auth_context.grant_type values
_GRANT_TYPE = {
    "iam_role":          "workload_identity",
    "api_key":           "api_key",
    "service_principal": "client_credentials",
    "delegated_oauth":   "authorization_code",
}

# v3 auth_context.delegation_type values
_DELEGATION_TYPE = {
    "iam_role":          "app_only",
    "api_key":           "app_only",
    "service_principal": "app_only",
    "delegated_oauth":   "on_behalf_of",
}

# ---------------------------------------------------------------------------
# Tool classification tables (per api_path)
# ---------------------------------------------------------------------------

# v3 agent_context.tool_name
_TOOL_NAME = {
    "/access/list":     "list_user_access",
    "/policy/evaluate": "evaluate_policy",
    "/ticket/create":   "create_ticket",
}

# v3 access_context.action_semantics
_TOOL_ACTION_SEMANTICS = {
    "/access/list":     "retrieval",
    "/policy/evaluate": "decision",
    "/ticket/create":   "mutation",
}

# v3 resource.resource_sensitivity
_TOOL_RISK_TIER = {
    "/access/list":     "internal",
    "/policy/evaluate": "internal",
    "/ticket/create":   "confidential",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_idp_provider(credential_type):
    if credential_type in _IDP_PROVIDER_MAP:
        return _IDP_PROVIDER_MAP[credential_type]
    if credential_type in ("service_principal", "delegated_oauth"):
        return OAUTH_IDP_PROVIDER
    return None


def _actor_subtype_from_arn(principal_arn):
    """Heuristic: derive v3 actor_subtype from IAM principal ARN."""
    if ":user/" in principal_arn:
        return "employee"
    if ":assumed-role/" in principal_arn or ":role/" in principal_arn:
        return "service_principal"
    return "unknown"


def _authorize_tool(api_path, session_assurance_level, mfa_satisfied):
    """
    Minimal policy evaluator stub.
    Returns (policy_decision, policy_id, approval_required, approval_present).
    Confidential-tier tools require session_assurance_level=high and mfa_satisfied=true.
    This generates policy_decision deny events for negative test scenarios.
    """
    risk_tier = _TOOL_RISK_TIER.get(api_path, "unknown")
    approval_required = risk_tier in ("confidential", "restricted")

    if approval_required:
        high_assurance = (
            session_assurance_level == "high"
            and str(mfa_satisfied).lower() == "true"
        )
        if not high_assurance:
            return "deny", "iga-tool-policy-v1", True, False
        return "allow", "iga-tool-policy-v1", True, True

    return "allow", "iga-tool-policy-v1", False, False


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

    print(json.dumps({"_debug_3lo": "step1_start", "workloadName": WORKLOAD_IDENTITY_NAME, "userId": user_identity}))
    wat_resp = client.get_workload_access_token_for_user_id(
        workloadName=WORKLOAD_IDENTITY_NAME,
        userId=user_identity
    )
    workload_token = wat_resp["workloadAccessToken"]
    print(json.dumps({"_debug_3lo": "step1_ok", "token_prefix": workload_token[:20]}))

    scopes = [s.strip() for s in OAUTH_SCOPES.split(",")]
    return_url = f"{OAUTH_CALLBACK_URL}?user_id={urllib.parse.quote(user_identity)}"
    print(json.dumps({"_debug_3lo": "step2_start", "provider": OAUTH_PROVIDER_NAME, "scopes": scopes}))
    token_resp = client.get_resource_oauth2_token(
        workloadIdentityToken=workload_token,
        resourceCredentialProviderName=OAUTH_PROVIDER_NAME,
        scopes=scopes,
        oauth2Flow="USER_FEDERATION",
        resourceOauth2ReturnUrl=return_url,
        forceAuthentication=False
    )
    print(json.dumps({
        "_debug_3lo": "step2_ok",
        "hasAccessToken": bool(token_resp.get("accessToken")),
        "hasAuthUrl": bool(token_resp.get("authorizationUrl"))
    }))

    access_token = token_resp.get("accessToken")
    if access_token:
        return {"access_token": access_token}

    authorization_url = token_resp.get("authorizationUrl", "")
    session_uri = token_resp.get("sessionUri", "")
    callback_with_params = (
        f"{OAUTH_CALLBACK_URL}?user_id={urllib.parse.quote(user_identity)}"
        f"&session_uri={urllib.parse.quote(session_uri)}"
    )
    return {
        "authorization_required": True,
        "authorization_url":      authorization_url,
        "callback_url":           callback_with_params,
        "session_uri":            session_uri,
    }


# ---------------------------------------------------------------------------
# Log emitters
# ---------------------------------------------------------------------------

def log_activity(
    *,
    request_id,
    user_identity,
    actor_subtype,
    agent_id,
    sub_agent_name,
    tool_name,
    tool_type,
    tool_risk_tier,
    action_semantics,
    mcp_server,
    downstream_system,
    downstream_operation,
    credential_type,
    auth_protocol,
    idp_provider,
    grant_type,
    delegation_type,
    execution_mode,
    session_assurance_level,
    mfa_satisfied,
    success,
    latency_ms,
    sanitized_arguments,
    orchestrating_agent_id=None,
    delegation_chain=None,
    delegated_principal_global_id=None,
    policy_decision=None,
    policy_id=None,
    policy_evaluated=None,
    approval_required=None,
    approval_present=None,
    error_type=None,
):
    payload = {
        "event_type":              "bedrock_tool_activity",
        "request_id":              request_id,
        "user_identity":           user_identity,
        "actor_subtype":           actor_subtype,
        "agent_id":                agent_id,
        "sub_agent_name":          sub_agent_name,
        "tool_name":               tool_name,
        "tool_type":               tool_type,
        "tool_risk_tier":          tool_risk_tier,
        "action_semantics":        action_semantics,
        "mcp_server":              mcp_server,          # kept for back-compat
        "downstream_system":       downstream_system,
        "downstream_operation":    downstream_operation,
        "credential_type":         credential_type,
        "auth_protocol":           auth_protocol,
        "idp_provider":            idp_provider,
        "grant_type":              grant_type,
        "delegation_type":         delegation_type,
        "execution_mode":          execution_mode,
        "session_assurance_level": session_assurance_level,
        "mfa_satisfied":           mfa_satisfied,
        "success":                 success,
        "latency_ms":              latency_ms,
        "sanitized_arguments":     sanitized_arguments,
    }
    if orchestrating_agent_id:
        payload["orchestrating_agent_id"] = orchestrating_agent_id
    if delegation_chain:
        payload["delegation_chain"] = delegation_chain
    if delegated_principal_global_id:
        payload["delegated_principal_global_id"] = delegated_principal_global_id
    if policy_decision is not None:
        payload["policy_decision"] = policy_decision
    if policy_id is not None:
        payload["policy_id"] = policy_id
    if policy_evaluated is not None:
        payload["policy_evaluated"] = policy_evaluated
    if approval_required is not None:
        payload["approval_required"] = approval_required
    if approval_present is not None:
        payload["approval_present"] = approval_present
    if error_type:
        payload["error_type"] = error_type
    print(json.dumps(payload))


def log_token_request(
    *,
    request_id,
    user_identity,
    agent_id,
    sub_agent_name,
    grant_type,
    credential_type,
    token_endpoint,
    delegated_principal=None,
    success,
    error_type=None,
):
    """Emits bedrock_token_request → v3 event_type=token_issuance."""
    payload = {
        "event_type":      "bedrock_token_request",
        "request_id":      request_id,
        "user_identity":   user_identity,
        "agent_id":        agent_id,
        "sub_agent_name":  sub_agent_name,
        "grant_type":      grant_type,
        "credential_type": credential_type,
        "token_endpoint":  token_endpoint,
        "success":         success,
    }
    if delegated_principal:
        payload["delegated_principal"] = delegated_principal
    if error_type:
        payload["error_type"] = error_type
    print(json.dumps(payload))


def log_resource_access(
    *,
    request_id,
    user_identity,
    agent_id,
    sub_agent_name,
    downstream_system,
    downstream_resource,
    downstream_operation,
    credential_type,
    delegated_principal=None,
    records_read=None,
    success,
    error_type=None,
):
    """Emits bedrock_resource_access → v3 event_type=resource_access."""
    payload = {
        "event_type":           "bedrock_resource_access",
        "request_id":           request_id,
        "user_identity":        user_identity,
        "agent_id":             agent_id,
        "sub_agent_name":       sub_agent_name,
        "downstream_system":    downstream_system,
        "downstream_resource":  downstream_resource,
        "downstream_operation": downstream_operation,
        "credential_type":      credential_type,
        "success":              success,
    }
    if delegated_principal:
        payload["delegated_principal"] = delegated_principal
    if records_read is not None:
        payload["records_read"] = records_read
    if error_type:
        payload["error_type"] = error_type
    print(json.dumps(payload))


# ---------------------------------------------------------------------------
# Bedrock response envelope
# ---------------------------------------------------------------------------

def bedrock_response(event, body, status_code=200):
    return {
        "messageVersion": event.get("messageVersion", "1.0"),
        "response": {
            "actionGroup":    event["actionGroup"],
            "apiPath":        event.get("apiPath", "/unknown"),
            "httpMethod":     event.get("httpMethod", "POST"),
            "httpStatusCode": status_code,
            "responseBody": {
                "application/json": {
                    "body": json.dumps(body)
                }
            },
        },
        "sessionAttributes":       event.get("sessionAttributes", {}),
        "promptSessionAttributes": event.get("promptSessionAttributes", {}),
    }


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

def call_mock_mcp_tool(tool_name, arguments, credential_type, user_identity):
    headers = {"Content-Type": "application/json"}

    if credential_type == "api_key":
        headers["x-api-key"] = get_secret(MOCK_API_KEY_SECRET_ARN)
    elif credential_type == "delegated_oauth":
        if USE_MOCK_OAUTH:
            headers["Authorization"] = "Bearer mock-user-delegated-token"
        else:
            result = get_3lo_token(user_identity)
            if result.get("authorization_required"):
                return result
            headers["Authorization"] = f"Bearer {result['access_token']}"
    elif credential_type == "service_principal":
        headers["Authorization"] = "Bearer mock-agent-owned-token"

    if not MOCK_MCP_URL:
        return {
            "mock": True,
            "tool_name": tool_name,
            "arguments": arguments,
            "result": {
                "accounts": [
                    {"application": "Salesforce", "account": "sf-" + arguments.get("user_email", "unknown")},
                    {"application": "Workday",    "account": "wd-" + arguments.get("user_email", "unknown")},
                ],
                "entitlements": [
                    "Salesforce:Reports:Read",
                    "Workday:Worker:Read",
                ],
            },
        }

    request_body = json.dumps({"tool_name": tool_name, "arguments": arguments}).encode("utf-8")
    req = urllib.request.Request(MOCK_MCP_URL, data=request_body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    start = time.time()

    session_attributes      = event.get("sessionAttributes", {}) or {}
    request_id              = session_attributes.get("request_id", context.aws_request_id)
    user_identity           = session_attributes.get("user_identity", "unknown")
    orchestrating_agent_id  = session_attributes.get("orchestrating_agent_id", "")
    execution_mode          = session_attributes.get("execution_mode", "unknown")
    session_assurance_level = session_attributes.get("session_assurance_level", "low")
    mfa_satisfied           = session_attributes.get("mfa_satisfied", "false")

    agent_info     = event.get("agent", {}) or {}
    agent_id       = agent_info.get("id", "unknown")
    sub_agent_name = agent_info.get("name", "unknown")

    api_path         = event.get("apiPath", "")
    tool_name        = _TOOL_NAME.get(api_path, api_path or "unknown_tool")
    action_semantics = _TOOL_ACTION_SEMANTICS.get(api_path, "unknown")
    tool_risk_tier   = _TOOL_RISK_TIER.get(api_path, "unknown")

    user_email      = get_parameter(event, "user_email") or "unknown@example.com"
    credential_type = session_attributes.get("credential_type", DEFAULT_CREDENTIAL_TYPE)
    auth_protocol   = _AUTH_PROTOCOL.get(credential_type, "unknown")
    idp_provider    = _get_idp_provider(credential_type)
    grant_type      = _GRANT_TYPE.get(credential_type, "unknown")
    delegation_type = _DELEGATION_TYPE.get(credential_type, "unknown")
    actor_subtype   = _actor_subtype_from_arn(user_identity)

    # Build delegation chain ARNs
    region     = os.environ.get("AWS_REGION", "us-east-1")
    account_id = AWS_ACCOUNT_ID or context.invoked_function_arn.split(":")[4]

    supervisor_global_id = (
        f"arn:aws:bedrock:{region}:{account_id}:agent/{orchestrating_agent_id}"
        if orchestrating_agent_id else ""
    )
    collaborator_global_id = (
        f"arn:aws:bedrock:{region}:{account_id}:agent/{orchestrating_agent_id}/collaborator/{sub_agent_name}"
        if orchestrating_agent_id else
        f"arn:aws:bedrock:{region}:{account_id}:agent/{agent_id}"
    )
    delegation_chain = [x for x in [user_identity, supervisor_global_id, collaborator_global_id] if x]

    delegated_principal_global_id = user_identity if credential_type == "delegated_oauth" else None

    sanitized_arguments = {
        "user_email_domain": user_email.split("@")[-1] if "@" in user_email else "unknown"
    }

    # Policy evaluation
    policy_decision, policy_id, approval_required, approval_present = _authorize_tool(
        api_path, session_assurance_level, mfa_satisfied
    )

    # Shared fields passed to every log_activity call
    _log_common = dict(
        request_id=request_id,
        user_identity=user_identity,
        actor_subtype=actor_subtype,
        agent_id=agent_id,
        sub_agent_name=sub_agent_name,
        tool_name=tool_name,
        tool_type="action_group",
        tool_risk_tier=tool_risk_tier,
        action_semantics=action_semantics,
        mcp_server="mock-access-mcp",
        downstream_system="mock-access-mcp",
        downstream_operation="POST",
        credential_type=credential_type,
        auth_protocol=auth_protocol,
        idp_provider=idp_provider,
        grant_type=grant_type,
        delegation_type=delegation_type,
        execution_mode=execution_mode,
        session_assurance_level=session_assurance_level,
        mfa_satisfied=mfa_satisfied,
        orchestrating_agent_id=orchestrating_agent_id,
        delegation_chain=delegation_chain,
        delegated_principal_global_id=delegated_principal_global_id,
        policy_decision=policy_decision,
        policy_id=policy_id,
        policy_evaluated=True,
        approval_required=approval_required,
        approval_present=approval_present,
        sanitized_arguments=sanitized_arguments,
    )

    if policy_decision == "deny":
        latency_ms = int((time.time() - start) * 1000)
        log_activity(**_log_common, success=False, latency_ms=latency_ms, error_type="policy_denied")
        return bedrock_response(
            event,
            {"error": "tool invocation denied by policy", "policy_id": policy_id},
            403,
        )

    # Emit token_issuance for mock OAuth paths.
    # Real 3LO token issuance is logged by oauth_callback_handler.py on consent completion.
    if credential_type == "service_principal" or (credential_type == "delegated_oauth" and USE_MOCK_OAUTH):
        log_token_request(
            request_id=request_id,
            user_identity=user_identity,
            agent_id=agent_id,
            sub_agent_name=sub_agent_name,
            grant_type=grant_type,
            credential_type=credential_type,
            token_endpoint="mock",
            delegated_principal=user_identity if credential_type == "delegated_oauth" else None,
            success=True,
        )

    try:
        tool_result = call_mock_mcp_tool(
            tool_name=tool_name,
            arguments={"user_email": user_email},
            credential_type=credential_type,
            user_identity=user_identity,
        )

        if tool_result.get("authorization_required"):
            latency_ms = int((time.time() - start) * 1000)
            log_activity(
                **_log_common,
                success=False,
                latency_ms=latency_ms,
                error_type="authorization_required",
            )
            return bedrock_response(event, tool_result, 200)

        latency_ms = int((time.time() - start) * 1000)

        log_activity(**_log_common, success=True, latency_ms=latency_ms)

        records_read = len((tool_result.get("result") or {}).get("accounts") or [])
        log_resource_access(
            request_id=request_id,
            user_identity=user_identity,
            agent_id=agent_id,
            sub_agent_name=sub_agent_name,
            downstream_system="mock-access-mcp",
            downstream_resource=api_path,
            downstream_operation="POST",
            credential_type=credential_type,
            delegated_principal=user_identity if credential_type == "delegated_oauth" else None,
            records_read=records_read,
            success=True,
        )

        return bedrock_response(event, tool_result, 200)

    except Exception as exc:
        latency_ms = int((time.time() - start) * 1000)
        log_activity(
            **_log_common,
            success=False,
            latency_ms=latency_ms,
            error_type=type(exc).__name__,
        )
        return bedrock_response(
            event,
            {"error": "tool invocation failed", "error_type": type(exc).__name__},
            500,
        )