import { Amplify } from "aws-amplify";
import {
  signIn, confirmSignIn, signOut, fetchAuthSession, getCurrentUser,
} from "aws-amplify/auth";

Amplify.configure({
  Auth: {
    Cognito: {
      userPoolId: process.env.NEXT_PUBLIC_USER_POOL_ID!,
      userPoolClientId: process.env.NEXT_PUBLIC_USER_POOL_CLIENT_ID!,
    },
  },
});

export type Role = "Admin" | "Doctor" | "Receptionist";

/** Start sign-in. Returns the next step so the UI can prompt for MFA or a new password. */
export async function startSignIn(username: string, password: string) {
  const { nextStep } = await signIn({ username, password });
  return nextStep.signInStep;
}

/** Answer a challenge (TOTP code, or a new permanent password on first login). */
export async function answerChallenge(response: string) {
  const { nextStep } = await confirmSignIn({ challengeResponse: response });
  return nextStep.signInStep;
}

/** Current user's role, read from the Cognito group claim in the ID token. */
export async function getRole(): Promise<Role | null> {
  const session = await fetchAuthSession();
  const groups = session.tokens?.idToken?.payload["cognito:groups"] as string[] | undefined;
  const known: Role[] = ["Admin", "Doctor", "Receptionist"];
  return known.find((r) => groups?.includes(r)) ?? null;
}

export async function getUsername() {
  try {
    const { username } = await getCurrentUser();
    return username;
  } catch {
    return null;
  }
}

/** Raw ID token for the Authorization header. Amplify refreshes it automatically. */
export async function getIdToken(): Promise<string | null> {
  const session = await fetchAuthSession();
  return session.tokens?.idToken?.toString() ?? null;
}

export async function logout() {
  await signOut();
}
