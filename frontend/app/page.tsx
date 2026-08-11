"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { startSignIn, answerChallenge, getUsername } from "@/lib/auth";

type Stage = "credentials" | "mfa" | "newPassword";

export default function LoginPage() {
  const router = useRouter();
  const [stage, setStage] = useState<Stage>("credentials");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [challenge, setChallenge] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Already signed in? Go straight through.
  useEffect(() => {
    getUsername().then((u) => u && router.replace("/dashboard"));
  }, [router]);

  function routeStep(step: string) {
    if (step === "DONE") return router.replace("/dashboard");
    if (step === "CONFIRM_SIGN_IN_WITH_TOTP_CODE") return setStage("mfa");
    if (step === "CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED") return setStage("newPassword");
    if (step === "CONTINUE_SIGN_IN_WITH_TOTP_SETUP") {
      setError("This account needs MFA enrolment. Run backend/login.py once to set it up.");
      return;
    }
    setError(`Unsupported sign-in step: ${step}`);
  }

  async function submitCredentials(e: React.FormEvent) {
    e.preventDefault();
    setError(""); setBusy(true);
    try {
      routeStep(await startSignIn(username.trim(), password));
    } catch (err: any) {
      // Deliberately generic: never reveal whether the username exists.
      setError(err?.name === "NotAuthorizedException"
        ? "Incorrect username or password."
        : err?.message ?? "Sign-in failed.");
    } finally { setBusy(false); }
  }

  async function submitChallenge(e: React.FormEvent) {
    e.preventDefault();
    setError(""); setBusy(true);
    try {
      routeStep(await answerChallenge(challenge));
      setChallenge("");
    } catch (err: any) {
      setError(stage === "mfa"
        ? "That code was not accepted. Wait for the next code and try again."
        : err?.message ?? "Could not complete sign-in.");
    } finally { setBusy(false); }
  }

  return (
    <div className="wrap" style={{ maxWidth: 420, paddingTop: 80 }}>
      <div className="card">
        <h1>SecureHealth</h1>
        <p className="muted">Clinic staff sign-in — multi-factor authentication required.</p>

        {error && <div className="err">{error}</div>}

        {stage === "credentials" && (
          <form onSubmit={submitCredentials}>
            <label>Username</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)}
                   autoComplete="username" required />
            <label>Password</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                   autoComplete="current-password" required />
            <div style={{ marginTop: 16 }}>
              <button disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
            </div>
          </form>
        )}

        {stage === "mfa" && (
          <form onSubmit={submitChallenge}>
            <label>Authentication code</label>
            <input value={challenge} onChange={(e) => setChallenge(e.target.value)}
                   inputMode="numeric" maxLength={6} placeholder="6-digit code" autoFocus required />
            <p className="muted">Enter the current code from your authenticator app.</p>
            <button disabled={busy}>{busy ? "Verifying…" : "Verify"}</button>
          </form>
        )}

        {stage === "newPassword" && (
          <form onSubmit={submitChallenge}>
            <label>Set a new password</label>
            <input type="password" value={challenge} onChange={(e) => setChallenge(e.target.value)}
                   autoComplete="new-password" autoFocus required />
            <p className="muted">
              At least 12 characters, with upper and lower case, a number and a symbol.
            </p>
            <button disabled={busy}>{busy ? "Saving…" : "Continue"}</button>
          </form>
        )}
      </div>
    </div>
  );
}
