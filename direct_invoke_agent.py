# client/direct_invoke_agent.py
import argparse
import json
import re
import sys
import time
import uuid
import webbrowser

import boto3


def invoke_agent(client, agent_id, agent_alias_id, session_id, message,
                 credential_type, user_identity):
    response = client.invoke_agent(
        agentId=agent_id,
        agentAliasId=agent_alias_id,
        sessionId=session_id,
        inputText=message,
        enableTrace=True,
        sessionState={
            "sessionAttributes": {
                "request_id": str(uuid.uuid4()),
                "user_identity": user_identity,
                "credential_type": credential_type
            }
        }
    )

    chunks = []
    for event in response["completion"]:
        if "chunk" in event:
            text = event["chunk"]["bytes"].decode("utf-8")
            chunks.append(text)
            print(text, end="")
        elif "trace" in event:
            print("\n\nTRACE EVENT:")
            print(event["trace"])

    return "".join(chunks)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--agent-alias-id", required=True)
    parser.add_argument("--message", required=True)
    parser.add_argument("--credential-type", default="iam_role")
    parser.add_argument("--user-identity", default="direct-cli-user")
    args = parser.parse_args()

    client = boto3.client("bedrock-agent-runtime", region_name=args.region)
    session_id = str(uuid.uuid4())

    response_text = invoke_agent(
        client, args.agent_id, args.agent_alias_id, session_id,
        args.message, args.credential_type, args.user_identity
    )

    # Check if the response contains an authorization URL (3LO consent needed)
    auth_url = None

    match = re.search(
        r"https://bedrock-agentcore\.[^\s\"'<>]+/identities/oauth2/authorize\?request_uri=[^\s\"'<>]+",
        response_text
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
            client, args.agent_id, args.agent_alias_id,
            str(uuid.uuid4()),  # ← new session, not the old session_id
            args.message, args.credential_type, args.user_identity
        )
    elif "authorization_required" in response_text or "/identities/oauth2/authorize" in response_text:
        print("\n\nAuthorization required but could not extract URL from response.")
        print("Check the agent response above for the authorization URL.")

    print()


if __name__ == "__main__":
    main()