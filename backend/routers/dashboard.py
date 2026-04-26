"""
/api/dashboard/summary

Cross-machine view for the executive overview. Computes everything in one
endpoint so the frontend doesn't have to fan out N requests.

Severity counts now combine BOTH key findings AND policy findings into a
single "what management cares about" tally.
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user
from models import UserAccount, TargetMachine, SSHKeyInventory, PolicyFinding
from schemas import FleetSummary
from risk import classify, algorithm_label, posture_score

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# A target is "silent" if its last scan is older than this:
SILENT_THRESHOLD = timedelta(days=7)


@router.get("/summary", response_model=FleetSummary)
def fleet_summary(
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
        ).all()
        if target_ids else []
    )
    policy_findings = (
        db.query(PolicyFinding).filter(
            PolicyFinding.target_id.in_(target_ids)
        ).all()
        if target_ids else []
    )

    # ----- Machine status counts -----
    now = datetime.utcnow()
    machines_reporting = 0
    machines_silent = 0
    machines_never_scanned = 0
    for t in targets:
        if t.last_scan_at is None:
            machines_never_scanned += 1
        elif (now - t.last_scan_at) > SILENT_THRESHOLD:
            machines_silent += 1
        else:
            machines_reporting += 1

    # ----- Key counts -----
    private_keys = sum(1 for k in keys if (k.key_kind or "") == "private")
    public_keys = sum(1 for k in keys if (k.key_kind or "") == "public")
    unique_fingerprints = len({k.fingerprint for k in keys if k.fingerprint})

    # ----- Severity tallies -----
    # Combine key findings + policy findings under one severity scale.
    severity_counts = Counter()
    per_machine_sev = defaultdict(lambda: Counter())

    for k in keys:
        sev, _, _ = classify(k)
        severity_counts[sev] += 1
        per_machine_sev[k.target_id][sev] += 1

    for f in policy_findings:
        sev = (f.severity or "").lower()
        if sev not in {"critical", "high", "medium", "info"}:
            continue
        severity_counts[sev] += 1
        per_machine_sev[f.target_id][sev] += 1

    # ----- Algorithm distribution -----
    algo_counts = Counter()
    for k in keys:
        algo_counts[algorithm_label(k)] += 1

    # ----- Top risk machines -----
    target_lookup = {t.id: t for t in targets}
    top_risk = []
    for tid, sev_counter in per_machine_sev.items():
        t = target_lookup.get(tid)
        if not t:
            continue
        top_risk.append({
            "id": t.id,
            "hostname": t.hostname,
            "critical": sev_counter.get("critical", 0),
            "high": sev_counter.get("high", 0),
            "medium": sev_counter.get("medium", 0),
            "key_count": sum(1 for k in keys if k.target_id == tid),
        })
    top_risk.sort(
        key=lambda m: (m["critical"], m["high"], m["medium"]),
        reverse=True,
    )
    top_risk = top_risk[:10]

    # ----- Shared keys (same fingerprint on >1 machine) -----
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
                "fingerprint": fp,
                "algorithm": algo,
                "bits": bits,
                "machine_count": len(tids),
                "hostnames": [target_lookup[tid].hostname for tid in tids
                              if tid in target_lookup],
            })
    shared.sort(key=lambda s: s["machine_count"], reverse=True)
    shared = shared[:20]

    score = posture_score({
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
    })

    return FleetSummary(
        total_machines=len(targets),
        machines_reporting=machines_reporting,
        machines_silent=machines_silent,
        machines_never_scanned=machines_never_scanned,
        total_keys=len(keys),
        unique_fingerprints=unique_fingerprints,
        private_keys=private_keys,
        public_keys=public_keys,
        findings_by_severity={
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
        },
        posture_score=score,
        algorithm_distribution=dict(algo_counts),
        top_risk_machines=top_risk,
        shared_keys=shared,
    )
