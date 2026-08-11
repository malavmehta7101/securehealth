"""SecureHealth patient records handler.

Routes:
    POST   /patients          create   (Admin, Doctor)
    GET    /patients?q=       search   (all roles; Receptionist redacted)
    GET    /patients/{id}     read     (all roles; Receptionist redacted)
    PUT    /patients/{id}     update   (Admin, Doctor)

Security pipeline on every request: identity from validated JWT claims ->
deny-by-default RBAC -> whitelist input validation -> KMS encryption /
SHA-256 integrity verification -> audit write.
"""
import common as c


def handler(event, _context):
    username, role = c.get_identity(event)

    # Deny-by-default: no recognised role -> no access, and it's audited.
    if role is None:
        c.write_audit(username, role, "PATIENT_ACCESS", "DENIED_NO_ROLE")
        return c.error(403, "forbidden", "No role assigned to this account.")

    method = event.get("httpMethod", "")
    path_params = event.get("pathParameters") or {}
    patient_id = path_params.get("id")

    try:
        if method == "POST":
            return create_patient(username, role, event)
        if method == "GET" and patient_id:
            return get_patient(username, role, patient_id)
        if method == "GET":
            return search_patients(username, role, event)
        if method == "PUT":
            return update_patient(username, role, patient_id, event)
        return c.error(405, "method_not_allowed", "Unsupported method.")
    except c.ValidationError as exc:
        c.write_audit(username, role, "VALIDATION_REJECT", "BLOCKED", patient_id, str(exc))
        return c.error(400, "validation_failed", str(exc))
    except c.IntegrityError:
        # Tamper detected: refuse to serve the record and raise a loud audit event.
        c.write_audit(username, role, "TAMPER_DETECTED", "ALERT", patient_id)
        print(f"[SECURITY-ALERT] Integrity failure on patient {patient_id}")
        return c.error(409, "integrity_failure",
                       "Record integrity verification failed. Access blocked and logged.")
    except Exception as exc:                                    # noqa: BLE001
        print(f"[ERROR] {type(exc).__name__}: {exc}")           # detail to logs only
        c.write_audit(username, role, "SERVER_ERROR", "FAIL", patient_id)
        return c.error(500, "server_error", "An unexpected error occurred.")


# ---------------------------------------------------------------- create -----
def create_patient(username, role, event):
    if not c.is_allowed(role, "patient:create"):
        c.write_audit(username, role, "PATIENT_CREATE", "DENIED_ROLE")
        return c.error(403, "forbidden", "Your role may not create patient records.")

    data = c.parse_body(event, require_all=True)

    record = {
        "patient_id": c.new_patient_id(),
        "first_name": data["first_name"],
        "last_name": data["last_name"],
        "date_of_birth": data["date_of_birth"],
        "health_card": data["health_card"],
        "email": data.get("email", ""),
        "phone": data.get("phone", ""),
        "clinical_notes": data.get("clinical_notes", ""),
        "allergies": data.get("allergies", ""),
        "created_at": c.now_iso(),
        "updated_at": c.now_iso(),
    }

    c.patients_table.put_item(Item=c.to_storage(record))
    c.write_audit(username, role, "PATIENT_CREATE", "OK", record["patient_id"])
    return c.ok({"patient": c.redact_for(role, record)}, status=201)


# ------------------------------------------------------------------ read -----
def get_patient(username, role, patient_id):
    if not c.is_allowed(role, "patient:read"):
        c.write_audit(username, role, "PATIENT_READ", "DENIED_ROLE", patient_id)
        return c.error(403, "forbidden", "Your role may not read patient records.")
    if not c.valid_patient_id(patient_id):
        raise c.ValidationError("Invalid patient id.")

    resp = c.patients_table.get_item(Key={"patient_id": patient_id})
    item = resp.get("Item")
    if not item:
        c.write_audit(username, role, "PATIENT_READ", "NOT_FOUND", patient_id)
        return c.error(404, "not_found", "Patient not found.")

    record = c.from_storage(item)          # verifies SHA-256 integrity
    c.write_audit(username, role, "PATIENT_READ", "OK", patient_id)
    return c.ok({"patient": c.redact_for(role, record)})


# ---------------------------------------------------------------- search -----
def search_patients(username, role, event):
    if not c.is_allowed(role, "patient:read"):
        c.write_audit(username, role, "PATIENT_SEARCH", "DENIED_ROLE")
        return c.error(403, "forbidden", "Your role may not search patient records.")

    params = event.get("queryStringParameters") or {}
    query = (params.get("q") or "").strip().lower()
    if len(query) > 50:
        raise c.ValidationError("Search term is too long.")

    # Scan is acceptable at demo scale; a GSI on last_name would be the
    # production choice and is noted as future work in the report.
    items = c.patients_table.scan(Limit=100).get("Items", [])

    results, flagged = [], 0
    for item in items:
        try:
            record = c.from_storage(item)
        except c.IntegrityError:
            # One bad record must not break the whole list; flag and skip it.
            flagged += 1
            c.write_audit(username, role, "TAMPER_DETECTED", "ALERT", item.get("patient_id"))
            continue
        haystack = f"{record['first_name']} {record['last_name']} {record['health_card']}".lower()
        if not query or query in haystack:
            results.append(c.redact_for(role, record))

    results.sort(key=lambda r: (r["last_name"].lower(), r["first_name"].lower()))
    c.write_audit(username, role, "PATIENT_SEARCH", "OK", detail=f"{len(results)} results")
    return c.ok({"patients": results, "count": len(results), "integrity_failures": flagged})


# ---------------------------------------------------------------- update -----
def update_patient(username, role, patient_id, event):
    if not c.is_allowed(role, "patient:update"):
        c.write_audit(username, role, "PATIENT_UPDATE", "DENIED_ROLE", patient_id)
        return c.error(403, "forbidden", "Your role may not modify patient records.")
    if not c.valid_patient_id(patient_id):
        raise c.ValidationError("Invalid patient id.")

    data = c.parse_body(event, require_all=False)
    if not data:
        raise c.ValidationError("No fields to update.")

    resp = c.patients_table.get_item(Key={"patient_id": patient_id})
    item = resp.get("Item")
    if not item:
        c.write_audit(username, role, "PATIENT_UPDATE", "NOT_FOUND", patient_id)
        return c.error(404, "not_found", "Patient not found.")

    record = c.from_storage(item)          # verify integrity BEFORE modifying
    record.update(data)
    record["updated_at"] = c.now_iso()

    c.patients_table.put_item(Item=c.to_storage(record))        # re-encrypt + re-hash
    c.write_audit(username, role, "PATIENT_UPDATE", "OK", patient_id,
                  detail=f"fields: {', '.join(sorted(data))}")
    return c.ok({"patient": c.redact_for(role, record)})
