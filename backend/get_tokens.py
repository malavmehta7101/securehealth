"""Fetch Cognito tokens for all three test roles and write them to .test-env.

Usage:
    python get_tokens.py
    source .test-env                 # Git Bash / macOS / Linux
    pytest tests/test_integration.py -v

Each account needs its permanent password set and MFA enrolled once via
login.py before this will work. .test-env is gitignored - it holds live tokens.
"""
import getpass
import os
import sys

import boto3

REGION = "ca-central-1"
CLIENT_ID = "4do8nu47e2osb6bb5hj96uhqri"
API_URL = "https://z4pz9ha8j6.execute-api.ca-central-1.amazonaws.com/v1"

ACCOUNTS = [
    ("admin1", "SECUREHEALTH_ADMIN_TOKEN"),
    ("doctor1", "SECUREHEALTH_DOCTOR_TOKEN"),
    ("reception1", "SECUREHEALTH_RECEPTION_TOKEN"),
]

idp = boto3.client("cognito-idp", region_name=REGION)


def sign_in(username):
    password = getpass.getpass(f"  password for {username}: ")
    resp = idp.initiate_auth(
        ClientId=CLIENT_ID,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    if resp.get("ChallengeName") == "SOFTWARE_TOKEN_MFA":
        code = input(f"  MFA code for {username}: ").strip()
        resp = idp.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName="SOFTWARE_TOKEN_MFA",
            Session=resp["Session"],
            ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": code},
        )
    if "AuthenticationResult" not in resp:
        raise RuntimeError(
            f"{username} needs first-time setup - run: python login.py {username}"
        )
    return resp["AuthenticationResult"]["IdToken"]


def main():
    lines = [f'export SECUREHEALTH_API_URL="{API_URL}"']
    for username, var in ACCOUNTS:
        print(f"\nSigning in as {username}...")
        try:
            lines.append(f'export {var}="{sign_in(username)}"')
            print(f"  ok")
        except Exception as exc:                                  # noqa: BLE001
            print(f"  FAILED: {exc}")
            print(f"  ({var} will be unset; its tests will be skipped)")

    with open(".test-env", "w") as fh:
        fh.write("\n".join(lines) + "\n")

    print("\nWrote .test-env (tokens valid ~1 hour). Next:")
    print("    source .test-env")
    print("    pytest tests/test_integration.py -v")


if __name__ == "__main__":
    sys.exit(main())
