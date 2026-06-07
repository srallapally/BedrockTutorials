# client/direct_invoke_agent.py
import argparse
import json
import re
import uuid
import webbrowser

import boto3


def _execution_mode(principal_arn):
    """Derive v3 auth_context.execution_mode from IAM principal ARN."""
    if ":user/" in principal_arn:
        return "interactive"
    return "non_interactive"


def _print_governance_trace(trace_event):
    """
    Print only governance-relevant trace frames; discard orchestration internals.
    Emits structured JSON lines so output is greppable.
    Bedrock trace events are doubly nested: event["trace"]["trace"] holds the typed frame.
    """
    trace = trace_event.get("trace", {}).get("trace", {})

    gt = trace.get("guardrailTrace")
    if gt:
        print(json.dumps({
            "trace_type":                "guardrail",
            "action":                    gt.get("action"),
            "input_assessment_count":    len(gt.get("inputAssessments", [])),
            "output_assessment_count":   len(gt.get("outputAssessments", [])),
        }))

    for kb_key in ("knowledgeBaseLookupInput", "knowledgeBaseLookupOutput"):
        kb = trace.get(kb_key)
        if kb:
            refs = kb.get("retrievedReferences", [])
            print(json.dumps({
                "trace_type":      "knowledge_base",
                "phase":           "input" if kb_key.endswith("Input") else "output",
                "knowledge_base_id": kb.get("knowledgeBaseId", ""),
                "records_retrieved": len(refs),
            }))


def invoke_agent(
    client, agent_id, agent_alias_id, session_id, message,
    credential_type, user_identity, session_assurance_level, mfa_satisfied,
):
    response = client.invoke_agent(
        agentId=agent_id,
        agentAliasId=agent_alias_id,
        sessionId=session_id,
        inputText=message,
        enableTrace=True,
        sessionState={
            "sessionAttributes": {
                "request_id":             str(uuid.uuid4()),
                "user_identity":          user_identity,
                "orchestrating_agent_id": agent_id,       # supervisor is its own orchestrator on direct invoke
                "credential_type":        credential_type,
                "execution_mode":         _execution_mode(user_identity),
                "idp_provider":           "aws-iam",
                "session_assurance_level": session_assurance_level,
                "mfa_satisfied":          str(mfa_satisfied).lower(),
            }
        },
    )

    chunks = []
    for event in response["completion"]:
        if "chunk" in event:
            text = event["chunk"]["bytes"].decode("utf-8")
            chunks.append(text)
            print(text, end="")
        elif "trace" in event:
            _print_governance_trace(event)

    return "".join(chunks)


def main():
    parser = argparse.ArgumentParser(
        description="Directly invoke a Bedrock agent alias and print governance trace events."
    )
    parser.add_argument("--region",                required=True)
    parser.add_argument("--agent-id",              required=True)
    parser.add_argument("--agent-alias-id",        required=True)
    parser.add_argument("--message",               required=True)
    parser.add_argument("--credential-type",       default="iam_role")
    parser.add_argument("--user-identity",         default=None,
                        help="IAM principal ARN. Defaults to STS GetCallerIdentity.")
    parser.add_argument("--session-assurance-level", default="low",
                        choices=["low", "medium", "high"],
                        help="Session assurance level passed to the tool Lambda (default: low).")
    parser.add_argument("--mfa-satisfied",         action="store_true", default=False,
                        help="Assert that MFA was satisfied for this session.")
    args = parser.parse_args()

    # Derive user identity from STS when not supplied
    if not args.user_identity:
        sts = boto3.client("sts", region_name=args.region)
        args.user_identity = sts.get_caller_identity()["Arn"]

    client = boto3.client("bedrock-agent-runtime", region_name=args.region)
    session_id = str(uuid.uuid4())

    response_text = invoke_agent(
        client,
        args.agent_id,
        args.agent_alias_id,
        session_id,
        args.message,
        args.credential_type,
        args.user_identity,
        args.session_assurance_level,
        args.mfa_satisfied,
    )

    # Check if the response contains an authorization URL (3LO consent needed)
    auth_url = None

    match = re.search(
        r"https://bedrock-agentcore\.[^\s\"'<>]+/identities/oauth2/authorize\?request_uri=[^\s\"'<>]+",
        response_text,
    )
    if match:
        auth_url = match.group(0).rstrip('",.)')

    if not auth_url and "authorization_url" in response_text:
        # Try parsing as JSON embedded in the response. The agent may wrap
        # the tool response in prose, so scan brace-delimited fragments.
        try:
            for segment in response_text.split("{"):
                try:
                    candidate = json.loads("{" + segment.split("}")[0] + "}")
                    if "authorization_url" in candidate:
                        auth_url = candidate["authorization_url"]
                        break
                except (json.JSONDecodeError, IndexError):
                    continue
        except Exception:
            pass

    if auth_url:
        print("\n\n--- 3LO Authorization Required ---")
        print(f"Opening browser for consent: {auth_url[:80]}...")
        webbrowser.open(auth_url)
        print("\nComplete the consent flow in your browser.")
        input("Press Enter after authorizing to retry...")

        print("\n--- Retrying agent invocation ---\n")
        invoke_agent(
            client,
            args.agent_id,
            args.agent_alias_id,
            str(uuid.uuid4()),      # new session for the retry
            args.message,
            args.credential_type,
            args.user_identity,
            args.session_assurance_level,
            args.mfa_satisfied,
        )
    elif "authorization_required" in response_text or "/identities/oauth2/authorize" in response_text:
        print("\n\nAuthorization required but could not extract URL from response.")
        print("Check the agent response above for the authorization URL.")

    print()


if __name__ == "__main__":
    main()