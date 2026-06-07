# setup/create_google_provider.py
import argparse

from bedrock_agentcore.services.identity import IdentityClient


def main():
    parser = argparse.ArgumentParser(
        description="Register a Google OAuth2 credential provider with AgentCore Identity."
    )
    parser.add_argument("--client-id", required=True, help="Google OAuth2 client ID")
    parser.add_argument("--client-secret", required=True, help="Google OAuth2 client secret")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    args = parser.parse_args()

    identity_client = IdentityClient(args.region)
    provider = identity_client.create_oauth2_credential_provider({
        "name": "google-provider",
        "credentialProviderVendor": "GoogleOauth2",
        "oauth2ProviderConfigInput": {
            "googleOauth2ProviderConfig": {
                "clientId": args.client_id,
                "clientSecret": args.client_secret
            }
        }
    })
    print(f"Created provider: {provider}")


if __name__ == "__main__":
    main()