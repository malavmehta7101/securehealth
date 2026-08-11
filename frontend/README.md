# SecureHealth Dashboard (Next.js)

Owner: Robert. Built against `docs/api-contract.md`.

## Setup
```bash
cd frontend
npm install
cp .env.local.example .env.local    # values come from the SAM stack outputs
npm run dev                          # http://localhost:3000
```

`.env.local` is gitignored — never commit it.

## Sign-in
Users are provisioned by an Admin (no self-signup). First login for a new account
requires MFA enrolment, which the CLI helper handles: `python ../backend/login.py <username>`.
After that, the web login flow is: password -> 6-digit TOTP code.

Test accounts: `admin1` (Admin), `doctor1` (Doctor), `reception1` (Receptionist).

## What to demo
- Sign in as `doctor1` -> full clinical fields visible.
- Sign in as `reception1` -> the same record shows `[REDACTED]` clinical fields.
- Sign in as `reception1` and try the New patient tab -> not offered; the API also
  returns 403 if called directly (the UI is not the control).
- Admin only: Audit log tab, showing every access and every denied attempt.
- Tamper demo: edit a record directly in the DynamoDB console, then open it here ->
  integrity alert, access blocked, event written to the audit log.

## Structure
- `lib/auth.ts` — Amplify config, sign-in/MFA challenges, role from the ID token claim
- `lib/api.ts`  — fetch wrapper that attaches the bearer token and maps API error codes
- `app/page.tsx` — login (password / MFA / first-login password change)
- `app/dashboard/page.tsx` — role-aware patient list, create form, detail view, audit log
