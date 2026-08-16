# SecureHealth — Demo Walkthrough

A step-by-step script for the live demonstration and for recording the backup
video. Follow it in order; each step builds the state the next one needs.

**Target time:** 5–6 minutes of demo inside the 15–18 minute presentation.
**Presenters:** Malav drives, Robert narrates, Zawad covers monitoring,
Cinderella covers testing.

---

## The repository

Everything lives in one Git repository. It is the single source of truth: if a
change isn't committed, it doesn't exist — we lost the same CORS fix three
times to files being copied over a working directory.

**Repo:** `https://github.com/malavmehta7101/securehealth`

### Getting a copy

```bash
git clone https://github.com/malavmehta7101/securehealth.git
cd securehealth
```

Clone to a plain local path such as `C:\dev\` — **not** into OneDrive, Dropbox
or any synced folder. Sync clients lock files inside `.git` mid-operation and
corrupt the repository.

### What is in it

```
backend/              The AWS application
  template.yaml       Infrastructure as code — the entire stack in one file
  src/handlers/       common.py holds the shared security pipeline;
                      patients.py, audit.py and health.py are the endpoints
  tests/              145 tests, each marked with its STRIDE category
  login.py            First login and MFA enrolment for one account
  get_tokens.py       Signs in as all three roles, writes .test-env
frontend/             Next.js dashboard
  lib/auth.ts         Cognito sign-in, MFA challenges, role from the token claim
  lib/api.ts          Fetch wrapper that attaches the bearer token
  app/                Login page and the role-aware dashboard
iot/                  Equipment-monitoring extension — a separate stack
docs/
  api-contract.md     The contract between frontend and backend
  TEST-MATRIX.md      Every test mapped to a threat and a control
  PHASE2.md           Security implementation notes
  MONITORING.md       Metrics, alarms and the dashboard
  evidence/           Screenshots and scan reports, with an index
README.md             Setup, deployment and troubleshooting
WALKTHROUGH.md        This file
```

Two files deserve a mention on their own if anyone asks during Q&A:

- **`backend/src/handlers/common.py`** — the security pipeline every request
  runs through: identity from validated claims, deny-by-default authorisation,
  whitelist validation, KMS encryption, SHA-256 verification, audit write. If a
  grader wants to see "where the security is", this is the file.
- **`backend/template.yaml`** — every security setting is declared here rather
  than clicked into a console, so the configuration is reviewable in version
  control and reproducible in any AWS account.

### What is deliberately **not** in it

`.gitignore` keeps all of these out, and they should never appear in a commit:

| Excluded | Why |
|---|---|
| `frontend/.env.local` | Stack-specific configuration |
| `backend/.test-env`, `token.txt` | Live bearer tokens |
| `iot/certs/`, `iot/firmware/secrets.h` | Device private keys and Wi-Fi credentials |
| `node_modules/`, `.aws-sam/`, `__pycache__/` | Build output |

If you ever commit a credential by accident, treat it as compromised: rotate it
first, then remove it from the repo.

### Working in it day to day

```bash
git pull                                  # start every session with this
# ... make changes ...
git add -A
git commit -m "Short description of what changed and why"
git push
```

Rules the team agreed on:

- **Infrastructure changes go in a commit**, never as a manual edit to a local
  copy. This is the lesson that cost us three separate debugging sessions.
- `docs/api-contract.md` is the contract — changes need agreement from Malav
  and Robert, because both the frontend and the backend build against it.
- Capture evidence screenshots into `docs/evidence/` **as you work**, not at the
  end, and name them with the numbering in that folder's README.

### Running it from a fresh clone

Someone with no prior setup can go from clone to working system by following
`README.md`. In short:

```bash
# One-time AWS account setup (README has the exact commands)
cd backend
sam build && sam deploy --guided     # deploys to your own AWS account
python login.py admin1               # set the password and enrol MFA

cd ../frontend
npm install
cp .env.local.example .env.local     # fill in from the stack outputs
npm run dev
```

Each team member deploys into **their own AWS account**. Malav's deployment is
the canonical demo environment — the recorded demo and the presentation both
point at it.

### For the submission

If the repository is submitted alongside the report, say so on the title slide
and mention that it contains the infrastructure as code, the test suite and the
evidence folder. Those three demonstrate "a working system, not just a design"
far better than screenshots alone.

Before handing over the link, check: repository visibility is set the way the
team intends, `git status` is clean, and the latest commit is pushed.

---

## Before you start (do this 15 minutes early)

Nothing here should happen on camera.

### Use Git Bash, not PowerShell

Every command in this walkthrough is written for **Git Bash**. `source .test-env`
is a bash builtin — in PowerShell it silently does nothing, leaving `$API` and
the token variables empty, and curl then fails with
`curl: (3) URL rejected: No host part in the URL`.

In VS Code, open the terminal dropdown next to `+` and choose **Git Bash**.

If you must use PowerShell, load the same values natively and remember that
environment variables need the `$env:` prefix there:

```powershell
Get-Content .test-env | ForEach-Object { if ($_ -match '^export (\w+)="(.*)"$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] } }
$API = "https://z4pz9ha8j6.execute-api.ca-central-1.amazonaws.com/v1"
# then use $env:SECUREHEALTH_ADMIN_TOKEN instead of $SECUREHEALTH_ADMIN_TOKEN
```

### Setup

```bash
# 1. Frontend running
cd /c/dev/securehealth/frontend
npm run dev                      # leave running at http://localhost:3000

# 2. Fresh tokens in a second terminal (they last one hour)
cd /c/dev/securehealth/backend
python get_tokens.py             # password + MFA code for all three accounts
source .test-env
API=https://z4pz9ha8j6.execute-api.ca-central-1.amazonaws.com/v1
```

Checklist:

- [ ] `npm run dev` running, browser open at `localhost:3000`, signed **out**
- [ ] Terminal is **Git Bash**, tokens loaded, `$API` set
- [ ] Verified with `echo $API` and `echo ${#SECUREHEALTH_ADMIN_TOKEN}`
      (expect the URL, and a length around 1000 — `0` means the tokens didn't load)
- [ ] AWS console open in a second browser tab, region **Canada (Central)**,
      on DynamoDB → `securehealth-patients` → Explore items
- [ ] Third tab on the CloudWatch dashboard `SecureHealth-Security`
- [ ] Sarah Chen's `first_name` reads **Sarah** (not `Eve`) — the demo tampers
      it live, so it must start clean
- [ ] Authenticator app open on your phone
- [ ] Terminal font size increased for the recording
- [ ] Backup video ready to play if the network fails
- [ ] `git status` clean and everything pushed — the repo link may be shared on the day

**Patient id used throughout:**
`2c8500aa-1eed-44dc-b1e7-000ea0fb1f8c` (Sarah Chen)

---

## Step 1 — The door is locked (30 s)

> "Before anything else: the API refuses anyone who isn't authenticated. This
> is rejected at the gateway, before a single line of our code runs."

```bash
curl.exe -i $API/health
```

**Expect:** `HTTP/1.1 401 Unauthorized` · `{"message":"Unauthorized"}`

Point out: no application code executed — API Gateway's Cognito authorizer
stopped it.

---

## Step 2 — Signing in requires more than a password (45 s)

Browser → `localhost:3000` → sign in as **`admin1`**.

> "Password first. But a password alone isn't enough — the system asks for a
> time-based code from an authenticator app. MFA is enforced on every account;
> it isn't optional."

Enter the 6-digit code. You land on the dashboard showing **admin1 · Admin**.

Point out: the role badge comes from a Cognito group claim inside the signed
token, not from anything the browser chose.

---

## Step 3 — The same record, two different roles (60 s)

Still as **admin1**: click **View** on Sarah Chen.

> "As an Admin I can see everything — allergies, clinical notes, the lot."

Sign out. Sign in as **`reception1`** (password + MFA).

> "Now the same record as a receptionist."

Open Sarah Chen again.

**Expect:** `clinical_notes` and `allergies` both show **`[REDACTED]`**;
name, date of birth, health card and phone remain visible.

> "A receptionist needs the demographics to book appointments. They don't need
> the clinical notes, so they never receive them — the fields are replaced on
> the server, before the response is sent."

Also point out: the **New patient** and **Audit log** tabs are gone for this role.

---

## Step 4 — The interface is not the control (45 s)

> "Hiding a button isn't security. Let's bypass the interface entirely and call
> the API directly with this receptionist's own valid token."

```bash
curl.exe -i -X POST $API/patients -H "Authorization: Bearer $SECUREHEALTH_RECEPTION_TOKEN" -H "Content-Type: application/json" -d '{"first_name":"Test","last_name":"User","date_of_birth":"1990-01-01","health_card":"2222222222"}'
```

**Expect:** `HTTP/1.1 403 Forbidden` ·
`{"error": "forbidden", "message": "Your role may not create patient records."}`

> "Authenticated, valid token, correct request format — and still refused,
> because authorisation is checked in the API, not in the browser."

---

## Step 5 — Malicious input never reaches the database (45 s)

```bash
curl.exe -i -X POST $API/patients -H "Authorization: Bearer $SECUREHEALTH_ADMIN_TOKEN" -H "Content-Type: application/json" -d '{"first_name":"Robert; DROP TABLE--","last_name":"Tables","date_of_birth":"1990-01-01","health_card":"1111111111"}'
```

**Expect:** `HTTP/1.1 400 Bad Request` ·
`"Field 'first_name' must be 1-50 letters, spaces, hyphens or apostrophes."`

> "Two things to notice. It's rejected before any database call. And the error
> names the field but never repeats what was sent back to us — otherwise the
> error message itself becomes a way to inject content."

---

## Step 6 — What is actually stored (45 s)

AWS console tab → DynamoDB → `securehealth-patients` → **Explore items** →
**Run** → open Sarah Chen → toggle **View DynamoDB JSON**.

> "This is the raw record as it sits in the database."

Point at:

- `clinical_notes_enc` and `allergies_enc` — long base64 blobs, unreadable
- `integrity` — the SHA-256 hash
- `first_name`, `health_card` — readable, because search needs them

> "Even with full access to the database, the clinical fields are ciphertext.
> The key that decrypts them lives in AWS KMS and never enters our code."

---

## Step 7 — Tamper detection (90 s) — the centrepiece

Still in the DynamoDB item editor:

> "Now let me act as an attacker who has already got into the database — the
> worst case. I'll change this patient's first name."

Change `first_name` from **`Sarah`** to **`Eve`** → **Save changes**.

Back to the terminal:

```bash
curl.exe -i $API/patients/2c8500aa-1eed-44dc-b1e7-000ea0fb1f8c -H "Authorization: Bearer $SECUREHEALTH_ADMIN_TOKEN"
```

**Expect:** `HTTP/1.1 409 Conflict` ·
`"Record integrity verification failed. Access blocked and logged."`

> "The hash no longer matches the record, so the system refuses to serve it.
> It would rather show nothing than show a medical record it can't vouch for."

Browser → sign in as **admin1** → **Patients**.

**Expect:** orange banner — *"1 record(s) failed integrity verification and were
withheld from these results."* Other patients still listed normally.

> "One bad record doesn't break the register — it's withheld and counted, and
> the user is told why."

Now restore it. DynamoDB → change `first_name` back to **`Sarah`** → Save →
refresh the browser.

**Expect:** banner gone, Sarah Chen back in the list.

> "Put the original value back and it verifies again. The check is exact and
> deterministic — which matters when the difference between 5mg and 50mg is a
> patient safety issue."

---

## Step 8 — Everything is on the record (45 s)

Browser → **Audit log** tab (Admin only).

**Expect:** rows showing `TAMPER_DETECTED` / **ALERT**, `VALIDATION_REJECT` /
**BLOCKED**, `PATIENT_READ` / OK, with user, role and timestamp.

> "Every action from the last five minutes is here — including the ones that
> were refused. Denials are recorded as deliberately as successes, because
> 'who tried' matters as much as 'who succeeded'."

Point out: only the Admin role can open this, and reading it is itself audited.

---

## Step 9 — Monitoring (Zawad, 45 s)

CloudWatch tab → dashboard `SecureHealth-Security`, time range **1h**.

**Expect:** spikes on *Integrity alerts*, *Denied access attempts* and *Input
validation rejections* — created by the last few minutes of this demo.

> "Those spikes are what we just did. Each is plotted against its alarm
> threshold. Tampering alarms on a single event, because one altered record
> means data has already been changed. Denials and rejections happen in normal
> use, so those alarm only on volume."

Optionally: CloudWatch → Alarms → six `SecureHealth-*` alarms.

---

## Step 10 — Testing (Cinderella, 30 s)

```bash
python -m pytest tests/ -q
```

**Expect:** `145 passed`

> "Everything you just watched runs automatically, 145 times, in about twenty
> seconds. Every test is tagged with the STRIDE threat it validates, so the
> suite maps directly onto our threat model."

---

## Optional — IoT extension (2 min, only if time allows)

Built after the assessed scope. Skip without hesitation if running long.

```bash
cd /c/dev/securehealth/iot
python simulate_device.py --endpoint <data-endpoint> --scenario excursion
```

> "A refrigerator monitor publishing over mutually authenticated TLS. As the
> temperature climbs past 8 degrees the alarm fires and an email goes out."

Then:

```bash
python simulate_device.py --endpoint <data-endpoint> --scenario spoof --count 3
```

> "And a forged payload is rejected and logged, never stored — the device is
> authenticated, but its data is still treated as untrusted input."

---

## Recovery — if something breaks on the day

| Symptom | Fix |
|---|---|
| `curl: (3) URL rejected: No host part in the URL` | You are in PowerShell, not Git Bash — the variables are empty. Switch terminal and re-run `source .test-env` |
| `401` on a call that should work | Token expired. `python get_tokens.py && source .test-env` |
| Frontend shows no data | Session expired — sign out and back in. Otherwise check the browser console for CORS |
| Patient list unexpectedly empty | A record is still tampered from a rehearsal. Restore `first_name` to `Sarah` |
| Dashboard graphs flat | Metrics lag 2–3 minutes. Say so and move on — the alarms list still proves the control |
| Anything else | Switch to the backup video. Don't debug on stage |

**Reset between rehearsals:**

```bash
aws dynamodb update-item --table-name securehealth-patients \
  --key '{"patient_id":{"S":"2c8500aa-1eed-44dc-b1e7-000ea0fb1f8c"}}' \
  --update-expression "SET first_name = :n" \
  --expression-attribute-values '{":n":{"S":"Sarah"}}' --region ca-central-1
```

---

## Likely questions

**Why hash the plaintext instead of the ciphertext?**
Hashing plaintext catches an edit to a clear field *and* a swapped encrypted
blob. Hashing ciphertext would only catch the second.

**Why delegate encryption to KMS instead of encrypting in code?**
The plaintext key never enters the function's memory, every use is recorded in
CloudTrail, and the key policy limits use to our Lambda roles. The trade-off is
a 4 KB limit per call, which is why clinical notes are capped at 2,000
characters.

**What stops someone copying one patient's encrypted notes onto another record?**
Each ciphertext is bound to its patient through a KMS encryption context, so a
blob moved to a different record fails to decrypt.

**Could an attacker just recompute the hash after editing?**
Not through the application — the hash is computed server-side and never
accepted from a client. Someone with direct database *and* application-code
access could, which is why the audit log and alarms exist as a second layer.

**Can the audit log be edited?**
Not through the application: there is no update or delete path, and the IAM
roles are write-only. It isn't cryptographically immutable — an S3 Object Lock
export is our documented next step.

**What would you fix first with another week?**
A global secondary index for patient search instead of a table scan, then
per-identity rate limiting, then the tamper-evident audit export.