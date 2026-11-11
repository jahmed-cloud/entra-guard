"""
Impact model: turns a scan's findings into "what should I fix first, and
what do I gain".

The dashboard's headline pass rate counts every check equally, so fixing a
Critical gap moves it exactly as much as fixing a Low one. Here each check is
weighted by its severity instead; the weighted score is the share of that
weight currently passing, and a failed check's `points` is how far fixing it
alone would raise the score.

Pure functions over plain dicts — no database or framework imports — so the
ranking is unit-tested directly.
"""

SEVERITY_WEIGHT = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
EFFORT_RANK = {"Low": 1, "Moderate": 2, "High": 3}
_DEFAULT_WEIGHT = SEVERITY_WEIGHT["Medium"]


def is_unverified(finding: dict) -> bool:
    """A check that could not actually inspect the tenant. The engine reports
    a Graph 403 (missing API permission) as status "failed" with the error in
    the evidence; that is a gap in coverage, not a confirmed weakness, so it
    must not count for or against the score."""
    if finding.get("status") not in ("passed", "failed"):
        return True
    evidence = finding.get("evidence")
    return finding.get("status") == "failed" and isinstance(evidence, dict) and bool(evidence.get("error"))


def _weight(finding: dict) -> int:
    return SEVERITY_WEIGHT.get(finding.get("severity"), _DEFAULT_WEIGHT)


def _effort(finding: dict) -> str:
    effort = finding.get("estimated_effort")
    return effort if effort in EFFORT_RANK else "Moderate"


def _score(passing_weight: float, total_weight: float):
    return round(passing_weight / total_weight * 100) if total_weight else None


def compute_impact(findings: list[dict], top_n: int = 5) -> dict:
    verified = [f for f in findings if not is_unverified(f)]
    failed = [f for f in verified if f["status"] == "failed"]
    total_weight = sum(_weight(f) for f in verified)
    passing_weight = total_weight - sum(_weight(f) for f in failed)

    def points(weight: float) -> float:
        return round(weight / total_weight * 100, 1) if total_weight else 0.0

    # Biggest gain first; among equals, the cheapest fix, then the engine's own
    # risk score. check_id last keeps the order stable between scans.
    ranked = sorted(failed, key=lambda f: (-_weight(f), EFFORT_RANK[_effort(f)],
                                           -float(f.get("score") or 0), str(f.get("check_id"))))
    actions = [
        {
            "check_id": f.get("check_id"),
            "severity": f.get("severity"),
            "effort": _effort(f),
            "points": points(_weight(f)),
            "affected_count": len(f.get("affected_resources") or []),
            "quick_win": _effort(f) == "Low" and f.get("severity") in ("Critical", "High"),
            "risk_description": f.get("risk_description"),
        }
        for f in ranked
    ]
    top = ranked[:max(top_n, 0)]
    quick_wins = [f for f in ranked if _effort(f) == "Low"]

    by_severity = {}
    for sev in SEVERITY_WEIGHT:
        sev_failed = [f for f in failed if f.get("severity") == sev]
        by_severity[sev] = {"failed": len(sev_failed), "points": points(sum(_weight(f) for f in sev_failed))}

    return {
        "weighted_score": _score(passing_weight, total_weight),
        "potential_score": _score(passing_weight + sum(_weight(f) for f in top), total_weight),
        "counts": {
            "passed": len(verified) - len(failed),
            "failed": len(failed),
            "unverified": len(findings) - len(verified),
        },
        "top_actions": actions[:max(top_n, 0)],
        "quick_wins": {
            "count": len(quick_wins),
            "points": points(sum(_weight(f) for f in quick_wins)),
        },
        "by_severity": by_severity,
    }
