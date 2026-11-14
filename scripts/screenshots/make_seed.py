"""Builds seed SQL for README screenshots: runs every real check against an
empty fake tenant to get genuine check_ids, severities and texts, then assigns
a plausible pass/fail mix and sample (fictional, contoso.com) affected objects.

Usage: make_seed.py <engine-dir> <target-id> <out.sql>
"""
import json
import random
import sys
import uuid

sys.path.insert(0, sys.argv[1])
from app import tasks  # noqa: E402

TARGET, OUT = sys.argv[2], sys.argv[3]
random.seed(7)


class EmptyGraph:
    def get(self, path, headers=None, **kwargs):
        return {"value": []}

    def get_all_pages(self, path, headers=None):
        return []

    def __getattr__(self, name):
        if name.startswith("get_"):
            return lambda *a, **k: []
        raise AttributeError(name)


results = {}
for fn in tasks.ALL_CHECKS:
    try:
        r = tasks.normalize_result(fn(EmptyGraph(), {}), fn.__name__)
    except Exception:
        continue
    if r:
        results[r["check_id"]] = r
checks = sorted(results.values(), key=lambda r: r["check_id"])

USERS = ["adele.vance", "alex.wilber", "megan.bowen", "lee.gu", "nestor.wilke", "pradeep.gupta", "lynne.robbins", "diego.siciliani"]
APPS = ["Legacy HR Sync", "Marketing Automation", "Finance Reporting Connector", "DevOps Deploy Bot", "Old Intranet SSO"]
FAIL_RATE = {"Critical": 0.30, "High": 0.34, "Medium": 0.30, "Low": 0.22}
BASE_SCORE = {"Critical": 9.0, "High": 7.0, "Medium": 4.5, "Low": 2.0}


def affected(check_id):
    n = random.randint(1, 6)
    if "-APP-" in check_id or "CONSENT" in check_id or "-SP-" in check_id:
        return [{"application": a} for a in random.sample(APPS, min(n, len(APPS)))]
    if "-CA-" in check_id or "IDENTITY" in check_id or "SSPR" in check_id:
        return [{"issue": "Tenant setting not configured as recommended"}]
    return [{"upn": f"{u}@contoso.com"} for u in random.sample(USERS, n)]


def q(v):
    return "'" + str(v).replace("'", "''") + "'"


def run_findings(fail_bias):
    """Returns (status, score, affected, evidence) per check for one scan."""
    rows = []
    for c in checks:
        roll = random.random()
        if roll < 0.03:
            rows.append((c, "error", 0.0, [], {"error": "Request timed out"}))
        elif roll < 0.03 + FAIL_RATE[c["severity"]] * fail_bias:
            score = round(min(10, BASE_SCORE[c["severity"]] + random.uniform(-1.0, 0.9)), 1)
            aff = affected(c["check_id"])
            rows.append((c, "failed", score, aff, {"affected_count": len(aff)}))
        else:
            rows.append((c, "passed", 0.0, [], {}))
    return rows


sql = ["BEGIN;", "DELETE FROM findings;", "DELETE FROM scan_runs;"]
# Seven daily scans, improving over time; the last one is "now".
biases = [1.55, 1.45, 1.4, 1.25, 1.15, 1.05, 1.0]
final_rows = None
for i, bias in enumerate(biases):
    days_ago = len(biases) - 1 - i
    rows = run_findings(bias)
    final_rows = rows
    rid = str(uuid.uuid4())
    passed = sum(1 for r in rows if r[1] == "passed")
    failed = sum(1 for r in rows if r[1] == "failed")
    skipped = len(rows) - passed - failed
    ts = f"now() - interval '{days_ago} days'"
    sql.append(
        "INSERT INTO scan_runs (id,target_id,status,triggered_by,checks_total,checks_passed,checks_failed,checks_skipped,"
        "started_at,completed_at,created_at,updated_at) VALUES "
        f"('{rid}','{TARGET}','completed','{'api' if days_ago == 0 else 'scheduler'}',{len(rows)},{passed},{failed},{skipped},"
        f"{ts} - interval '4 minutes',{ts},{ts} - interval '4 minutes',{ts});")
    if days_ago:
        continue  # findings only for the latest scan — that's all the UI reads
    for c, status, score, aff, ev in rows:
        sql.append(
            "INSERT INTO findings (id,scan_run_id,target_id,check_id,status,severity,score,affected_resources,evidence,"
            "risk_description,remediation_steps,estimated_effort,first_seen_at,last_seen_at,created_at,updated_at) VALUES "
            f"('{uuid.uuid4()}','{rid}','{TARGET}',{q(c['check_id'])},'{status}',{q(c['severity'])},{score},"
            f"{q(json.dumps(aff))}::jsonb,{q(json.dumps(ev))}::jsonb,{q(c['risk_description'])},{q(c['remediation_steps'])},"
            f"{q(c['estimated_effort'])},{ts},{ts},{ts},{ts});")
sql.append("COMMIT;")
open(OUT, "w", encoding="utf-8", newline="\n").write("\n".join(sql) + "\n")
f = [r for r in final_rows if r[1] == "failed"]
print(f"{len(checks)} checks; latest scan: {sum(1 for r in final_rows if r[1]=='passed')} passed, {len(f)} failed "
      f"({sum(1 for r in f if r[0]['severity']=='Critical')} critical), {sum(1 for r in final_rows if r[1]=='error')} errors")
