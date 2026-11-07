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

    passed = summary["pass"]
    warns = summary["warn"]
    fails = summary["fail"]
    infos = summary["info"]

    # Scoring: pass=100, info=80, warn=40, fail=0
    checkable = total - infos
    if checkable == 0:
        score = 80
    else:
        score = int(((passed * 100) + (warns * 40)) / checkable)

    # Penalty for critical failures
    if fails > 0:
        score = max(0, score - (fails * 10))

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
            if item["status"] == "fail":
                recommendations.append({
                    "priority": "critical",
                    "title": item["title"],
                    "detail": item.get("detail", ""),
                    "setting": item.get("setting"),
                    "category": cat["category"],
                })
            elif item["status"] == "warn":
                recommendations.append({
                    "priority": "recommended",
                    "title": item["title"],
                    "detail": item.get("detail", ""),
                    "setting": item.get("setting"),
                    "category": cat["category"],
                })

    # Sort: critical first
    recommendations.sort(key=lambda r: 0 if r["priority"] == "critical" else 1)

    return {
        "score": score,
        "grade": grade,
        "color": color,
        "description": description,
        "summary": summary,
        "recommendations": recommendations[:10],
        "report": report,
    }
