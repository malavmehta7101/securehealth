"""SecureHealth login helper.

Handles the Cognito auth challenges (NEW_PASSWORD_REQUIRED, MFA setup and
SOFTWARE_TOKEN_MFA) and prints an IdToken you can use with curl/Postman.

Usage:
    python login.py <username>

First run per user: sets a permanent password and enrols TOTP MFA.
Later runs: password + 6-digit code only.

Requires: pip install boto3
"""
import base64
import getpass
import sys

import boto3

REGION = "ca-central-1"
CLIENT_ID = "4do8nu47e2osb6bb5hj96uhqri"

idp = boto3.client("cognito-idp", region_name=REGION)


def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: python login.py <username>")
    username = sys.argv[1]
    password = getpass.getpass("Password: ")

    resp = idp.initiate_auth(
        ClientId=CLIENT_ID,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )

    # 1) First login with a temporary password
    if resp.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
        new_pw = getpass.getpass("Set a permanent password (12+ chars, upper/lower/digit/symbol): ")
        resp = idp.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=resp["Session"],
            ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": new_pw},
        )

    # 2) Enrol a TOTP authenticator (only happens once per user)
    if resp.get("ChallengeName") == "MFA_SETUP":
        assoc = idp.associate_software_token(Session=resp["Session"])
        print("\n" + "=" * 60)
        print("SECRET KEY (add to your authenticator app FIRST):")
        print("   ", assoc["SecretCode"])
        print("=" * 60)
        print("In your app: Add account -> Enter setup key -> paste the above")
        print("Name it 'securehealth-%s', type: Time-based\n" % username)
        input("Press Enter once the account is added and showing a code...")

        session = assoc["Session"]
        verify = None
        for attempt in range(1, 6):
            code = input(f"Enter the CURRENT 6-digit code (attempt {attempt}/5): ").strip()
            try:
                verify = idp.verify_software_token(
                    Session=session, UserCode=code, FriendlyDeviceName="securehealth-cli"
                )
                break
            except idp.exceptions.EnableSoftwareTokenMFAException:
                print("  Code mismatch. Wait for the app to show a NEW code, then retry.")
                print("  (If it keeps failing, your PC clock may be off - see README.)")
        if verify is None:
            sys.exit("MFA setup failed after 5 attempts.")

        resp = idp.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName="MFA_SETUP",
            Session=verify["Session"],
            ChallengeResponses={"USERNAME": username},
        )

    # 3) Normal MFA challenge on subsequent logins
    if resp.get("ChallengeName") == "SOFTWARE_TOKEN_MFA":
        code = input("MFA code: ").strip()
        resp = idp.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName="SOFTWARE_TOKEN_MFA",
            Session=resp["Session"],
            ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": code},
        )

    token = resp["AuthenticationResult"]["IdToken"]
    print("\n=== IdToken (expires in 1 hour) ===")
    print(token)
    print("\nTest it with:")
    print(f'  curl.exe -i https://z4pz9ha8j6.execute-api.{REGION}.amazonaws.com/v1/health -H "Authorization: Bearer <token>"')


if __name__ == "__main__":
    main()
