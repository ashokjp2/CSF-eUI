from csf_backend import security_check


GRADE_MAP = {
    (90, 101): ("A", "success", "Excellent security posture"),
    (75, 90): ("B", "info", "Good security, minor improvements possible"),
    (60, 75): ("C", "warning", "Fair security, several items need attention"),
    (40, 60): ("D", "danger", "Poor security, significant issues found"),
    (0, 40): ("F", "danger", "Critical security gaps, immediate action needed"),
}


def calculate_score():
    report = security_check.run_full_check()
    summary = report["summary"]

    total = summary["total"]
    if total == 0:
        return {"score": 0, "grade": "?", "color": "default", "description": "No checks ran"}

    fails = summary["fail"]

    # Weighted scoring: each pass/warn/fail item is worth its weight (1 low, 2 normal, 3 critical).
    # pass earns all of it, warn 40%, fail nothing. info and accepted items do not count.
    earned = possible = 0.0
    for cat in report["checks"]:
        for item in cat["items"]:
            w = item.get("weight") or (3 if item["status"] == "fail" else 2)
            if item["status"] == "pass":
                earned += w
                possible += w
            elif item["status"] == "warn":
                earned += 0.4 * w
                possible += w
            elif item["status"] == "fail":
                possible += w
    score = int(earned * 100 / possible) if possible else 80

    # Extra penalty for critical (weight 3) failures: a public database or a Docker socket
    # mount should sink the score far more than a cosmetic warning.
    critical = sum(1 for c in report["checks"] for i in c["items"] if i["status"] == "fail" and (i.get("weight") or 3) >= 3)
    score = max(0, score - critical * 8 - (fails - critical) * 3)

    score = max(0, min(100, score))

    grade = "?"
    color = "default"
    description = ""
    for (lo, hi), (g, c, d) in GRADE_MAP.items():
        if lo <= score < hi:
            grade = g
            color = c
            description = d
            break

    # Top recommendations
    recommendations = []
    for cat in report["checks"]:
        for item in cat["items"]:
            if item["status"] in ("fail", "warn"):
                recommendations.append({
                    "priority": "critical" if item["status"] == "fail" else "recommended",
                    "id": item.get("id"),
                    "title": item["title"],
                    "detail": item.get("detail", ""),
                    "setting": item.get("setting"),
                    "fix_value": item.get("fix_value"),
                    "fix": item.get("fix"),
                    "link": item.get("link"),
                    "weight": item.get("weight", 2),
                    "changed": item.get("changed"),
                    "category": cat["category"],
                })

    # Sort: critical first, then by weight (impact)
    recommendations.sort(key=lambda r: (0 if r["priority"] == "critical" else 1, -r["weight"]))

    return {
        "score": score,
        "grade": grade,
        "color": color,
        "description": description,
        "summary": summary,
        "recommendations": recommendations[:10],
        "report": report,
    }
