# bedrock-agent-tools/oauth_callback_handler.py
import json
import logging
import os
import re
import urllib.parse

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ.get("AWS_REGION", "us-east-1")
SESSION_URI_RE = re.compile(r"^urn:ietf:params:oauth:request_uri:[a-zA-Z0-9\-._~]+$")


def _get_identity_client():
    return boto3.client("bedrock-agentcore", region_name=REGION)


def _decode_query_value(value):
    if value is None:
        return None

    decoded = str(value).strip().strip('"\'')

    # API Gateway usually decodes query parameters, but depending on integration
    # shape or manual testing, the callback can still receive an encoded value
    # such as urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A....
    for _ in range(3):
        next_decoded = urllib.parse.unquote_plus(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded

    return decoded


def _normalize_session_uri(raw_session_uri):
    session_uri = _decode_query_value(raw_session_uri)
    if not session_uri:
        return None

    if not SESSION_URI_RE.fullmatch(session_uri):
        raise ValueError(
            "invalid session_uri/session_id; expected "
            "urn:ietf:params:oauth:request_uri:<id>, got: "
            f"{session_uri!r}"
        )

    return session_uri


def lambda_handler(event, context):
    qs = event.get("queryStringParameters", {}) or {}

    # AgentCore redirects with session_id. Keep session_uri for backward
    # compatibility with earlier manual callback URLs.
    raw_session_uri = qs.get("session_uri") or qs.get("session_id")
    raw_user_id = qs.get("user_id")

    if not raw_session_uri:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "missing session_uri or session_id query parameter"})
        }

    if not raw_user_id:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "missing user_id query parameter"})
        }

    try:
        session_uri = _normalize_session_uri(raw_session_uri)
        user_id = _decode_query_value(raw_user_id)

        client = _get_identity_client()

        # Complete the 3LO session binding. Do not call
        # get_workload_access_token_for_user_id here; CompleteResourceTokenAuth
        # only needs the same user identifier plus the AgentCore session URI.
        client.complete_resource_token_auth(
            userIdentifier={"userId": user_id},
            sessionUri=session_uri
        )

        logger.info("3LO session binding completed for user_id=%s", user_id)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "text/html"},
            "body": "<html><body><h2>Authorization complete.</h2><p>You may close this window and retry your agent request.</p></body></html>"
        }

    except Exception as exc:
        logger.error("3LO callback failed: %s", exc)
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "callback processing failed", "detail": str(exc)})
        }
