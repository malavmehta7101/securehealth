import { getIdToken } from "./auth";

const BASE = process.env.NEXT_PUBLIC_API_URL!;

export interface Patient {
  patient_id: string;
  first_name: string;
  last_name: string;
  date_of_birth: string;
  health_card: string;
  email?: string;
  phone?: string;
  clinical_notes?: string;   // "[REDACTED]" for Receptionists
  allergies?: string;
  created_at?: string;
  updated_at?: string;
}

export interface AuditEvent {
  event_time: string;
  user: string;
  role: string;
  action: string;
  outcome: string;
  patient_id?: string;
  detail?: string;
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = await getIdToken();
  if (!token) throw new ApiError(401, "no_session", "Your session has expired. Please sign in again.");

  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(init.headers || {}),
    },
  });

  const text = await res.text();
  const body = text ? JSON.parse(text) : {};

  if (!res.ok) {
    // 409 = SHA-256 integrity failure (tamper detected); surfaced prominently in the UI.
    throw new ApiError(res.status, body.error ?? "error", body.message ?? "Request failed.");
  }
  return body as T;
}

export const api = {
  health: () => request<{ user: string; role: string }>("/health"),

  searchPatients: (q = "") =>
    request<{ patients: Patient[]; count: number; integrity_failures: number }>(
      `/patients?q=${encodeURIComponent(q)}`
    ),

  getPatient: (id: string) => request<{ patient: Patient }>(`/patients/${id}`),

  createPatient: (data: Partial<Patient>) =>
    request<{ patient: Patient }>("/patients", { method: "POST", body: JSON.stringify(data) }),

  updatePatient: (id: string, data: Partial<Patient>) =>
    request<{ patient: Patient }>(`/patients/${id}`, { method: "PUT", body: JSON.stringify(data) }),

  audit: (limit = 50) =>
    request<{ day: string; count: number; events: AuditEvent[] }>(`/audit?limit=${limit}`),
};
