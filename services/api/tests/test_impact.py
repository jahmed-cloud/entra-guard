from conftest import FakeSession, bearer, use_db


def f(check_id, status="failed", severity="High", effort="Low", score=5.0, affected=0, evidence=None):
    return {"check_id": check_id, "status": status, "severity": severity, "estimated_effort": effort,
            "score": score, "affected_resources": [{}] * affected, "evidence": evidence or {},
            "risk_description": f"risk of {check_id}"}


def impact(findings, top_n=5):
    from app.services.impact import compute_impact
    return compute_impact(findings, top_n)


def test_empty_scan_has_no_score():
    result = impact([])
    assert result["weighted_score"] is None and result["potential_score"] is None
    assert result["top_actions"] == []
    assert result["counts"] == {"passed": 0, "failed": 0, "unverified": 0}


def test_score_is_weighted_by_severity():
    # 1 Critical failing (weight 10) vs 1 Low passing (weight 1): the plain
    # pass rate says 50%, the weighted score says 9%.
    result = impact([f("A", severity="Critical"), f("B", status="passed", severity="Low")])
    assert result["weighted_score"] == 9
    assert result["top_actions"][0]["points"] == 90.9
    assert result["potential_score"] == 100


def test_all_passing_is_100():
    result = impact([f("A", status="passed"), f("B", status="passed", severity="Critical")])
    assert result["weighted_score"] == 100 and result["top_actions"] == []


def test_unverified_checks_do_not_move_the_score():
    base = [f("A", severity="Critical"), f("B", status="passed", severity="High")]
    noise = [
        f("C", status="error", severity="Critical"),
        # Graph 403: the engine stores it as "failed" with the error in evidence.
        f("D", status="failed", severity="Critical", evidence={"error": "403 Forbidden"}),
    ]
    with_noise = impact(base + noise)
    assert with_noise["weighted_score"] == impact(base)["weighted_score"]
    assert with_noise["counts"] == {"passed": 1, "failed": 1, "unverified": 2}
    assert [a["check_id"] for a in with_noise["top_actions"]] == ["A"]


def test_ranking_prefers_severity_then_cheaper_fix_then_risk_score():
    result = impact([
        f("HIGH-LOW-EFFORT", severity="High", effort="Low"),
        f("CRIT-HIGH-EFFORT", severity="Critical", effort="High"),
        f("CRIT-LOW-EFFORT-B", severity="Critical", effort="Low", score=7.0),
        f("CRIT-LOW-EFFORT-A", severity="Critical", effort="Low", score=9.0),
        f("LOW", severity="Low", effort="Low"),
    ])
    assert [a["check_id"] for a in result["top_actions"]] == [
        "CRIT-LOW-EFFORT-A", "CRIT-LOW-EFFORT-B", "CRIT-HIGH-EFFORT", "HIGH-LOW-EFFORT", "LOW"]


def test_quick_wins_are_low_effort_critical_or_high():
    result = impact([
        f("A", severity="Critical", effort="Low", affected=3),
        f("B", severity="Critical", effort="High"),
        f("C", severity="Medium", effort="Low"),
    ])
    by_id = {a["check_id"]: a for a in result["top_actions"]}
    assert by_id["A"]["quick_win"] and not by_id["B"]["quick_win"] and not by_id["C"]["quick_win"]
    assert by_id["A"]["affected_count"] == 3
    assert result["quick_wins"]["count"] == 2  # A and C are low effort


def test_top_n_limits_actions_and_potential_score():
    findings = [f(f"C{i}", severity="High") for i in range(10)]
    result = impact(findings, top_n=3)
    assert len(result["top_actions"]) == 3
    assert result["weighted_score"] == 0 and result["potential_score"] == 30


def test_points_add_up_to_the_gap():
    result = impact([f("A", severity="Critical"), f("B", severity="Medium"), f("C", status="passed", severity="High")], top_n=25)
    assert round(sum(a["points"] for a in result["top_actions"])) == 100 - result["weighted_score"]


def test_unknown_severity_and_effort_do_not_crash():
    result = impact([f("A", severity=None, effort="Weeks"), f("B", status="passed", severity="Info")])
    assert result["weighted_score"] == 50
    assert result["top_actions"][0]["effort"] == "Moderate"


def test_impact_endpoint_with_no_completed_scan(client):
    use_db(FakeSession(None))  # no completed run
    r = client.get("/api/v1/findings/impact", headers=bearer(role="viewer"))
    assert r.status_code == 200
    assert r.json()["scan_run_id"] is None and r.json()["weighted_score"] is None


def test_impact_endpoint_requires_login(client):
    assert client.get("/api/v1/findings/impact").status_code == 401
