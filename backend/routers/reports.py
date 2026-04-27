"""
PDF audit reports.

  GET /api/reports/audit/{target_id}  - per-machine audit report
  GET /api/reports/fleet              - estate-wide summary report

Both return application/pdf with a Content-Disposition that prompts
the browser to download the file.
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user
from models import UserAccount, TargetMachine, SSHKeyInventory, PolicyFinding
from risk import classify, algorithm_label, posture_score
from pdf_reports import build_machine_report, build_fleet_report

router = APIRouter(prefix="/reports", tags=["reports"])

SILENT_THRESHOLD = timedelta(days=7)


def _format_dt(dt) -> str:
    if dt is None:
        return "never"
    return dt.strftime("%Y-%m-%d %H:%M UTC")


@router.get("/audit/{target_id}")
def per_machine_report(
    target_id: int,
    db: Session = Depends(get_db),
    user: UserAccount = Depends(get_current_user),
):
    target = db.query(TargetMachine).filter(
        TargetMachine.id == target_id,
        TargetMachine.user_id == user.id,
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    keys = db.query(SSHKeyInventory).filter(
        SSHKeyInventory.target_id == target.id
    ).all()
    policy_rows = db.query(PolicyFinding).filter(
        PolicyFinding.target_id == target.id
    ).all()

    # Classify keys, build the machine-side severity tally + finding lists.
    key_findings = []
    severity_counts = Counter()
    algo_counts = Counter()
    keys_for_table = []

    for k in keys:
        sev, findings, recs = classify(k)
        algo_counts[algorithm_label(k)] += 1
        if sev != "info":
            severity_counts[sev] += 1
            for i, msg in enumerate(findings):
                key_findings.append({
                    "severity": sev,
                    "title": msg,
                    "evidence": k.file_path,
                    "recommendation": recs[i] if i < len(recs) else "",
                })
        keys_for_table.append({
            "severity": sev,
            "username": k.username,
            "file_path": k.file_path,
            "key_algorithm": k.key_algorithm,
            "key_bits": k.key_bits,
            "permissions": k.permissions,
            "key_kind": k.key_kind,
        })

    policy_findings_for_pdf = []
    for f in policy_rows:
        sev = (f.severity or "").lower()
        if sev not in {"critical", "high", "medium", "info"}:
            continue
        if sev != "info":
            severity_counts[sev] += 1
        policy_findings_for_pdf.append({
            "severity": sev,
            "title": f.title,
            "description": f.description,
            "category": f.category,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
            "file_path": f.file_path,
        })

    score = posture_score({
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
    })

    machine = {
        "hostname": target.hostname,
        "ip_address": target.ip_address,
        "operating_system": target.operating_system,
        "status": target.status,
        "last_scan_at_str": _format_dt(target.last_scan_at),
    }

    pdf_bytes = build_machine_report(
        user_name=user.name or user.email,
        user_email=user.email,
        machine=machine,
        severity_counts=dict(severity_counts),
        posture_score=score,
        keys=keys_for_table,
        key_findings=key_findings,
        policy_findings=policy_findings_for_pdf,
        algorithm_distribution=dict(algo_counts),
    )

    safe_host = "".join(c if c.isalnum() or c in "-_" else "_"
                        for c in (target.hostname or f"target{target.id}"))
    filename = f"aunix_audit_{safe_host}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/fleet")
def fleet_report(
    db: Session = Depends(get_db),
    user: UserAccount = Depends(get_current_user),
):
    targets = db.query(TargetMachine).filter(
        TargetMachine.user_id == user.id
    ).all()
    target_ids = [t.id for t in targets]

    keys = (
        db.query(SSHKeyInventory).filter(
            SSHKeyInventory.target_id.in_(target_ids)
        ).all() if target_ids else []
    )
    policy = (
        db.query(PolicyFinding).filter(
            PolicyFinding.target_id.in_(target_ids)
        ).all() if target_ids else []
    )

    now = datetime.utcnow()
    machines_reporting = sum(
        1 for t in targets if t.last_scan_at and (now - t.last_scan_at) <= SILENT_THRESHOLD
    )
    machines_silent = sum(
        1 for t in targets if t.last_scan_at and (now - t.last_scan_at) > SILENT_THRESHOLD
    )
    machines_never = sum(1 for t in targets if t.last_scan_at is None)

    # Severity tallies + per-machine breakdown
    severity_counts = Counter()
    per_machine = defaultdict(lambda: Counter())
    algo_counts = Counter()

    for k in keys:
        sev, _, _ = classify(k)
        algo_counts[algorithm_label(k)] += 1
        if sev != "info":
            severity_counts[sev] += 1
            per_machine[k.target_id][sev] += 1

    for f in policy:
        sev = (f.severity or "").lower()
        if sev in {"critical", "high", "medium"}:
            severity_counts[sev] += 1
            per_machine[f.target_id][sev] += 1

    # Top risk machines
    target_lookup = {t.id: t for t in targets}
    keys_per_target = Counter(k.target_id for k in keys)
    top_risk = []
    for tid, sev_c in per_machine.items():
        t = target_lookup.get(tid)
        if not t:
            continue
        top_risk.append({
            "id": t.id,
            "hostname": t.hostname,
            "critical": sev_c.get("critical", 0),
            "high": sev_c.get("high", 0),
            "medium": sev_c.get("medium", 0),
            "key_count": keys_per_target.get(tid, 0),
        })
    top_risk.sort(key=lambda m: (m["critical"], m["high"], m["medium"]),
                  reverse=True)
    top_risk = top_risk[:10]

    # Shared keys (same fingerprint on >1 machine)
    fp_to_targets = defaultdict(set)
    fp_meta = {}
    for k in keys:
        if not k.fingerprint:
            continue
        fp_to_targets[k.fingerprint].add(k.target_id)
        if k.fingerprint not in fp_meta:
            fp_meta[k.fingerprint] = (k.key_algorithm, k.key_bits)
    shared = []
    for fp, tids in fp_to_targets.items():
        if len(tids) > 1:
            algo, bits = fp_meta.get(fp, (None, None))
            shared.append({
                "fingerprint": fp, "algorithm": algo, "bits": bits,
                "machine_count": len(tids),
                "hostnames": [target_lookup[tid].hostname for tid in tids
                              if tid in target_lookup],
            })
    shared.sort(key=lambda s: s["machine_count"], reverse=True)

    score = posture_score({
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
    })

    fleet_summary = {
        "total_machines": len(targets),
        "machines_reporting": machines_reporting,
        "machines_silent": machines_silent,
        "machines_never_scanned": machines_never,
        "total_keys": len(keys),
        "unique_fingerprints": len({k.fingerprint for k in keys if k.fingerprint}),
        "findings_by_severity": dict(severity_counts),
        "posture_score": score,
        "algorithm_distribution": dict(algo_counts),
        "top_risk_machines": top_risk,
        "shared_keys": shared[:20],
    }

    machines_for_pdf = []
    for t in targets:
        sev = per_machine.get(t.id, Counter())
        machines_for_pdf.append({
            "hostname": t.hostname,
            "operating_system": t.operating_system,
            "last_scan_at_str": _format_dt(t.last_scan_at),
            "key_count": keys_per_target.get(t.id, 0),
            "severity_counts": dict(sev),
        })

    pdf_bytes = build_fleet_report(
        user_name=user.name or user.email,
        user_email=user.email,
        fleet_summary=fleet_summary,
        machines=machines_for_pdf,
    )

    filename = f"aunix_fleet_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
