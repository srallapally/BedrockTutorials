# bedrock-agent-tools/frontdoor_handler.py
#
# Front door Lambda: authenticates callers, enforces ALLOWED_PRINCIPALS,
# threads session attributes into InvokeAgent, and emits governance log events.
#
# Evidence stream: tutorial-scope CloudWatch logs only.
# Log group is set at deployment via --logging-config LogGroup=/agent-governance/agent-gateway.
# This file is NOT part of the bedrock-core-tools-inventory product.
import json
import os
import time
import uuid

import boto3

bedrock_runtime = boto3.client("bedrock-agent-runtime")

AGENT_ID       = os.environ["AGENT_ID"]        # fail closed — required
AGENT_ALIAS_ID = os.environ["AGENT_ALIAS_ID"]  # fail closed — required
ALLOWED_PRINCIPALS = {
    p.strip()
    for p in os.environ.get("ALLOWED_PRINCIPALS", "").split(",")
    if p.strip()
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_principal(event):
    """Extract IAM principal ARN from API Gateway event context.
    Handles REST API (requestContext.identity.userArn) and
    HTTP API v2 (requestContext.authorizer.iam.userArn) shapes.
    """
    ctx = event.get("requestContext", {})
    arn = ctx.get("identity", {}).get("userArn")
    if not arn:
        arn = ctx.get("authorizer", {}).get("iam", {}).get("userArn")
    return arn or "unknown"


def _execution_mode(principal_arn):
    """v3 auth_context.execution_mode derived from IAM principal ARN."""
    if ":user/" in principal_arn:
        return "interactive"
    return "non_interactive"


def _authorize(principal_arn):
    """Returns (policy_decision, policy_id).
    Empty ALLOWED_PRINCIPALS allows all principals (tutorial default).
    """
    if ALLOWED_PRINCIPALS and principal_arn not in ALLOWED_PRINCIPALS:
        return "deny", "frontdoor-policy-v1"
    return "allow", "frontdoor-policy-v1"


# ---------------------------------------------------------------------------
# Log emitters
# ---------------------------------------------------------------------------

def log_authentication(
    *,
    request_id,
    principal_arn,
    auth_method,
    execution_mode,
    idp_provider,
    session_assurance_level,
    mfa_satisfied,
    policy_decision,
    authorized,
    failure_reason=None,
):
    """Emits bedrock_authentication → v3 event_type=authentication."""
    payload = {
        "event_type":              "bedrock_authentication",
        "request_id":              request_id,
        "principal_arn":           principal_arn,
        "auth_method":             auth_method,
        "execution_mode":          execution_mode,
        "idp_provider":            idp_provider,
        "session_assurance_level": session_assurance_level,
        "mfa_satisfied":           mfa_satisfied,
        "policy_decision":         policy_decision,
        "authorized":              authorized,
    }
    if failure_reason:
        payload["failure_reason"] = failure_reason
    print(json.dumps(payload))


def log_agent_invocation(
    *,
    request_id,
    user_identity,
    agent_id,
    agent_alias_id,
    invocation_phase,
    execution_mode,
    session_assurance_level,
    policy_decision,
    policy_id,
    tool_calls_count=None,
    guardrail_actions_count=None,
    knowledge_base_queries_count=None,
    session_duration_ms=None,
    success=None,
):
    """Emits bedrock_agent_invocation → v3 event_type=agent_invocation."""
    payload = {
        "event_type":              "bedrock_agent_invocation",
        "request_id":              request_id,
        "user_identity":           user_identity,
        "agent_id":                agent_id,
        "agent_alias_id":          agent_alias_id,
        "invocation_phase":        invocation_phase,
        "execution_mode":          execution_mode,
        "session_assurance_level": session_assurance_level,
        "policy_decision":         policy_decision,
        "policy_id":               policy_id,
    }
    if tool_calls_count is not None:
        payload["tool_calls_count"] = tool_calls_count
    if guardrail_actions_count is not None:
        payload["guardrail_actions_count"] = guardrail_actions_count
    if knowledge_base_queries_count is not None:
        payload["knowledge_base_queries_count"] = knowledge_base_queries_count
    if session_duration_ms is not None:
        payload["session_duration_ms"] = session_duration_ms
    if success is not None:
        payload["success"] = success
    print(json.dumps(payload))


def _emit_trace_events(trace_events, request_id, user_identity, agent_id):
    """
    Walk collected trace events and emit structured records for guardrail
    and knowledge base frames.
    Tutorial-scope evidence only — not collected by activity_logs.py.
    Bedrock trace events are doubly nested: event["trace"]["trace"].
    """
    # Guardrail Bedrock action → v3 guardrail_action enum
    _GUARDRAIL_ACTION_MAP = {
        "blocked":    "block",
        "intervened": "redact",
        "none":       "allow",
    }

    for trace_event in trace_events:
        inner = trace_event.get("trace", {}).get("trace", {})

        # Guardrail trace — top level within inner trace object
        gt = inner.get("guardrailTrace")
        if gt:
            assessments = gt.get("inputAssessments") or gt.get("outputAssessments") or []
            guardrail_id = assessments[0].get("guardrailId", "") if assessments else ""
            phase  = "input" if gt.get("inputAssessments") else "output"
            action = gt.get("action", "NONE").lower()
            print(json.dumps({
                "event_type":                 "bedrock_guardrail_trace",
                "request_id":                 request_id,
                "user_identity":              user_identity,
                "agent_id":                   agent_id,
                "guardrail_id":               guardrail_id,
                "guardrail_action":           _GUARDRAIL_ACTION_MAP.get(action, action),
                "guardrail_evaluation_phase": phase,
                "input_assessments":          len(gt.get("inputAssessments") or []),
                "output_assessments":         len(gt.get("outputAssessments") or []),
            }))

        # KB lookup — may appear at top level or inside orchestrationTrace
        orch   = inner.get("orchestrationTrace", {})
        kb_in  = (
            inner.get("knowledgeBaseLookupInput")
            or orch.get("invocationInput", {}).get("knowledgeBaseLookupInput")
        )
        kb_out = (
            inner.get("knowledgeBaseLookupOutput")
            or orch.get("observation", {}).get("knowledgeBaseLookupOutput")
        )
        if kb_in or kb_out:
            refs = (kb_out or {}).get("retrievedReferences") or []
            print(json.dumps({
                "event_type":        "bedrock_kb_trace",
                "request_id":        request_id,
                "user_identity":     user_identity,
                "agent_id":          agent_id,
                "knowledge_base_id": (kb_in or {}).get("knowledgeBaseId", ""),
                "records_retrieved": len(refs),
            }))


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    start      = time.time()
    request_id = str(uuid.uuid4())

    principal_arn  = _get_principal(event)
    execution_mode = _execution_mode(principal_arn)
    policy_decision, policy_id = _authorize(principal_arn)

    body = json.loads(event.get("body") or "{}")
    session_assurance_level = str(body.get("session_assurance_level", "low"))
    mfa_satisfied           = str(body.get("mfa_satisfied", False)).lower()

    authorized = policy_decision == "allow"

    # bedrock_authentication — emitted on every request, authorized or not
    log_authentication(
        request_id=request_id,
        principal_arn=principal_arn,
        auth_method="sigv4",
        execution_mode=execution_mode,
        idp_provider="aws-iam",
        session_assurance_level=session_assurance_level,
        mfa_satisfied=mfa_satisfied,
        policy_decision=policy_decision,
        authorized=authorized,
        failure_reason="unauthorized_principal" if not authorized else None,
    )

    if not authorized:
        return {
            "statusCode": 403,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "not authorized", "request_id": request_id}),
        }

    message         = body.get("message", "")
    session_id      = body.get("session_id") or str(uuid.uuid4())
    credential_type = body.get("credential_type", "iam_role")

    # bedrock_agent_invocation (started)
    log_agent_invocation(
        request_id=request_id,
        user_identity=principal_arn,
        agent_id=AGENT_ID,
        agent_alias_id=AGENT_ALIAS_ID,
        invocation_phase="started",
        execution_mode=execution_mode,
        session_assurance_level=session_assurance_level,
        policy_decision=policy_decision,
        policy_id=policy_id,
    )

    chunks            = []
    trace_events      = []
    tool_calls        = 0
    guardrail_actions = 0
    kb_queries        = 0

    try:
        response = bedrock_runtime.invoke_agent(
            agentId=AGENT_ID,
            agentAliasId=AGENT_ALIAS_ID,
            sessionId=session_id,
            inputText=message,
            enableTrace=True,
            sessionState={
                "sessionAttributes": {
                    "request_id":              request_id,
                    "user_identity":           principal_arn,
                    "orchestrating_agent_id":  AGENT_ID,
                    "credential_type":         credential_type,
                    "execution_mode":          execution_mode,
                    "idp_provider":            "aws-iam",
                    "session_assurance_level": session_assurance_level,
                    "mfa_satisfied":           mfa_satisfied,
                }
            },
        )

        for completion_event in response["completion"]:
            if "chunk" in completion_event:
                chunks.append(completion_event["chunk"]["bytes"].decode("utf-8"))

            elif "trace" in completion_event:
                trace_events.append(completion_event)
                inner  = completion_event.get("trace", {}).get("trace", {})
                orch   = inner.get("orchestrationTrace", {})
                inv_in = orch.get("invocationInput", {})

                if inner.get("guardrailTrace"):
                    guardrail_actions += 1

                if (
                    inner.get("knowledgeBaseLookupInput")
                    or inv_in.get("knowledgeBaseLookupInput")
                ):
                    kb_queries += 1

                if inv_in.get("actionGroupInvocationInput"):
                    tool_calls += 1

        session_duration_ms = int((time.time() - start) * 1000)

        # bedrock_agent_invocation (completed)
        log_agent_invocation(
            request_id=request_id,
            user_identity=principal_arn,
            agent_id=AGENT_ID,
            agent_alias_id=AGENT_ALIAS_ID,
            invocation_phase="completed",
            execution_mode=execution_mode,
            session_assurance_level=session_assurance_level,
            policy_decision=policy_decision,
            policy_id=policy_id,
            tool_calls_count=tool_calls,
            guardrail_actions_count=guardrail_actions,
            knowledge_base_queries_count=kb_queries,
            session_duration_ms=session_duration_ms,
            success=True,
        )

        _emit_trace_events(trace_events, request_id, principal_arn, AGENT_ID)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "request_id":                   request_id,
                "response":                     "".join(chunks),
                "tool_calls_count":             tool_calls,
                "guardrail_actions_count":      guardrail_actions,
                "knowledge_base_queries_count": kb_queries,
            }),
        }

    except Exception as exc:
        session_duration_ms = int((time.time() - start) * 1000)

        log_agent_invocation(
            request_id=request_id,
            user_identity=principal_arn,
            agent_id=AGENT_ID,
            agent_alias_id=AGENT_ALIAS_ID,
            invocation_phase="completed",
            execution_mode=execution_mode,
            session_assurance_level=session_assurance_level,
            policy_decision=policy_decision,
            policy_id=policy_id,
            tool_calls_count=tool_calls,
            guardrail_actions_count=guardrail_actions,
            knowledge_base_queries_count=kb_queries,
            session_duration_ms=session_duration_ms,
            success=False,
        )

        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "error":      "agent invocation failed",
                "error_type": type(exc).__name__,
                "request_id": request_id,
            }),
        }