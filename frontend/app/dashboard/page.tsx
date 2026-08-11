"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getRole, getUsername, logout, Role } from "@/lib/auth";
import { api, ApiError, Patient, AuditEvent } from "@/lib/api";

type Tab = "patients" | "new" | "audit";

const EMPTY: Partial<Patient> = {
  first_name: "", last_name: "", date_of_birth: "", health_card: "",
  email: "", phone: "", clinical_notes: "", allergies: "",
};

export default function Dashboard() {
  const router = useRouter();
  const [role, setRole] = useState<Role | null>(null);
  const [user, setUser] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("patients");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [patients, setPatients] = useState<Patient[]>([]);
  const [selected, setSelected] = useState<Patient | null>(null);
  const [query, setQuery] = useState("");
  const [tamperCount, setTamperCount] = useState(0);
  const [form, setForm] = useState<Partial<Patient>>(EMPTY);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [busy, setBusy] = useState(false);

  const canWrite = role === "Admin" || role === "Doctor";
  const isAdmin = role === "Admin";

  useEffect(() => {
    (async () => {
      const [r, u] = await Promise.all([getRole(), getUsername()]);
      if (!u) return router.replace("/");
      setRole(r); setUser(u);
    })();
  }, [router]);

  const load = useCallback(async (q = "") => {
    setError(""); setBusy(true);
    try {
      const res = await api.searchPatients(q);
      setPatients(res.patients);
      setTamperCount(res.integrity_failures ?? 0);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load patients.");
    } finally { setBusy(false); }
  }, []);

  useEffect(() => { if (role) load(); }, [role, load]);

  async function openPatient(id: string) {
    setError("");
    try {
      const { patient } = await api.getPatient(id);
      setSelected(patient);
    } catch (err) {
      // 409 = SHA-256 mismatch: the record was altered outside the application.
      if (err instanceof ApiError && err.status === 409) {
        setError("⚠ INTEGRITY ALERT — this record failed its SHA-256 verification and may have been tampered with. Access blocked and logged.");
      } else {
        setError(err instanceof ApiError ? err.message : "Could not open record.");
      }
    }
  }

  async function submitNew(e: React.FormEvent) {
    e.preventDefault();
    setError(""); setNotice(""); setBusy(true);
    try {
      const payload = Object.fromEntries(
        Object.entries(form).filter(([, v]) => v !== "")
      ) as Partial<Patient>;
      const { patient } = await api.createPatient(payload);
      setNotice(`Record created for ${patient.first_name} ${patient.last_name}.`);
      setForm(EMPTY); setTab("patients"); load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create record.");
    } finally { setBusy(false); }
  }

  async function loadAudit() {
    setError(""); setBusy(true);
    try {
      setEvents((await api.audit(100)).events);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load audit log.");
    } finally { setBusy(false); }
  }

  if (!role) return <div className="wrap"><p className="muted">Loading…</p></div>;

  return (
    <div className="wrap">
      <div className="bar">
        <div>
          <h1>SecureHealth</h1>
          <span className="muted">{user} · </span><span className="tag">{role}</span>
        </div>
        <button className="ghost" onClick={async () => { await logout(); router.replace("/"); }}>
          Sign out
        </button>
      </div>

      <nav style={{ marginBottom: 16 }}>
        <button className={tab === "patients" ? "" : "ghost"} onClick={() => { setTab("patients"); setSelected(null); }}>
          Patients
        </button>
        {canWrite && (
          <button className={tab === "new" ? "" : "ghost"} onClick={() => setTab("new")}>
            New patient
          </button>
        )}
        {isAdmin && (
          <button className={tab === "audit" ? "" : "ghost"} onClick={() => { setTab("audit"); loadAudit(); }}>
            Audit log
          </button>
        )}
      </nav>

      {error && <div className="err">{error}</div>}
      {notice && <div className="card" style={{ borderColor: "#0a7c42" }}>{notice}</div>}
      {tamperCount > 0 && (
        <div className="alert">
          <strong>{tamperCount} record(s) failed integrity verification</strong> and were withheld
          from these results. The events have been written to the audit log.
        </div>
      )}

      {tab === "patients" && !selected && (
        <div className="card">
          <div className="row">
            <div style={{ flex: 1 }}>
              <label>Search by name or health card</label>
              <input value={query} onChange={(e) => setQuery(e.target.value)}
                     onKeyDown={(e) => e.key === "Enter" && load(query)} />
            </div>
            <button onClick={() => load(query)} disabled={busy}>Search</button>
            <button className="ghost" onClick={() => { setQuery(""); load(); }}>Clear</button>
          </div>

          <table style={{ marginTop: 18 }}>
            <thead>
              <tr><th>Name</th><th>Date of birth</th><th>Health card</th><th></th></tr>
            </thead>
            <tbody>
              {patients.map((p) => (
                <tr key={p.patient_id}>
                  <td>{p.last_name}, {p.first_name}</td>
                  <td>{p.date_of_birth}</td>
                  <td>{p.health_card}</td>
                  <td><button className="ghost" onClick={() => openPatient(p.patient_id)}>View</button></td>
                </tr>
              ))}
              {!patients.length && !busy && (
                <tr><td colSpan={4} className="muted">No records found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <div className="card">
          <div className="bar">
            <h2>{selected.first_name} {selected.last_name}</h2>
            <button className="ghost" onClick={() => setSelected(null)}>Back</button>
          </div>
          <div className="grid">
            <div><label>Date of birth</label><div>{selected.date_of_birth}</div></div>
            <div><label>Health card</label><div>{selected.health_card}</div></div>
            <div><label>Email</label><div>{selected.email || "—"}</div></div>
            <div><label>Phone</label><div>{selected.phone || "—"}</div></div>
          </div>
          <label>Allergies</label>
          <div className={selected.allergies === "[REDACTED]" ? "redacted" : ""}>
            {selected.allergies || "—"}
          </div>
          <label>Clinical notes</label>
          <div className={selected.clinical_notes === "[REDACTED]" ? "redacted" : ""}>
            {selected.clinical_notes || "—"}
          </div>
          {role === "Receptionist" && (
            <p className="muted" style={{ marginTop: 14 }}>
              Clinical fields are hidden for your role. They are decrypted server-side only
              for authorised roles.
            </p>
          )}
        </div>
      )}

      {tab === "new" && canWrite && (
        <div className="card">
          <h2>New patient record</h2>
          <form onSubmit={submitNew}>
            <div className="grid">
              <div><label>First name *</label>
                <input value={form.first_name} required
                       onChange={(e) => setForm({ ...form, first_name: e.target.value })} /></div>
              <div><label>Last name *</label>
                <input value={form.last_name} required
                       onChange={(e) => setForm({ ...form, last_name: e.target.value })} /></div>
              <div><label>Date of birth *</label>
                <input type="date" value={form.date_of_birth} required
                       onChange={(e) => setForm({ ...form, date_of_birth: e.target.value })} /></div>
              <div><label>Health card (10 digits) *</label>
                <input value={form.health_card} required maxLength={10}
                       onChange={(e) => setForm({ ...form, health_card: e.target.value })} /></div>
              <div><label>Email</label>
                <input type="email" value={form.email}
                       onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
              <div><label>Phone (10 digits)</label>
                <input value={form.phone} maxLength={10}
                       onChange={(e) => setForm({ ...form, phone: e.target.value })} /></div>
            </div>
            <label>Allergies (encrypted at rest)</label>
            <input value={form.allergies}
                   onChange={(e) => setForm({ ...form, allergies: e.target.value })} />
            <label>Clinical notes (encrypted at rest)</label>
            <textarea rows={4} value={form.clinical_notes}
                      onChange={(e) => setForm({ ...form, clinical_notes: e.target.value })} />
            <p className="muted">
              All fields are re-validated server-side; clinical fields are encrypted with
              AES-256 before storage and protected by a SHA-256 integrity hash.
            </p>
            <button disabled={busy}>{busy ? "Saving…" : "Create record"}</button>
          </form>
        </div>
      )}

      {tab === "audit" && isAdmin && (
        <div className="card">
          <div className="bar">
            <h2>Audit log — today</h2>
            <button className="ghost" onClick={loadAudit} disabled={busy}>Refresh</button>
          </div>
          <table>
            <thead>
              <tr><th>Time (UTC)</th><th>User</th><th>Role</th><th>Action</th><th>Outcome</th></tr>
            </thead>
            <tbody>
              {events.map((e, i) => (
                <tr key={i}>
                  <td>{e.event_time.slice(11, 19)}</td>
                  <td>{e.user}</td>
                  <td>{e.role}</td>
                  <td>{e.action}</td>
                  <td style={{ color: e.outcome.startsWith("DENIED") || e.outcome === "ALERT" ? "#b42318" : undefined }}>
                    {e.outcome}
                  </td>
                </tr>
              ))}
              {!events.length && !busy && <tr><td colSpan={5} className="muted">No events yet today.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
