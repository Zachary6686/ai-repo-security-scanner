from typing import Any, Dict, List


SEVERITY_WEIGHTS = {
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
}

CONFIDENCE_WEIGHTS = {
    "HIGH": 1.0,
    "MEDIUM": 0.8,
    "LOW": 0.6,
}


def calculate_file_risk_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculate a transparent risk score for one file.

    Scoring logic:
    - HIGH = 10
    - MEDIUM = 5
    - LOW = 2
    - confidence multiplier:
        HIGH = 1.0
        MEDIUM = 0.8
        LOW = 0.6
    - bonus if multiple HIGH findings exist in the same file
    """
    if not findings:
        return 0

    raw_score = 0.0
    high_count = 0

    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        confidence = str(finding.get("confidence", "MEDIUM")).upper()

        severity_weight = SEVERITY_WEIGHTS.get(severity, 2)
        confidence_weight = CONFIDENCE_WEIGHTS.get(confidence, 0.8)

        raw_score += severity_weight * confidence_weight

        if severity == "HIGH":
            high_count += 1

    # 同一个文件多个高危，额外加分
    if high_count >= 2:
        raw_score += 5
    if high_count >= 4:
        raw_score += 5

    return int(round(raw_score))


def calculate_repository_risk_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculate repository risk score from 0 to 100.

    This score is intentionally simple and explainable:
    - total weighted findings
    - extra bonus for many HIGH findings
    - normalized to a max of 100
    """
    if not findings:
        return 0

    raw_score = 0.0
    high_count = 0
    medium_count = 0

    file_groups = group_findings_by_file(findings)

    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        confidence = str(finding.get("confidence", "MEDIUM")).upper()

        severity_weight = SEVERITY_WEIGHTS.get(severity, 2)
        confidence_weight = CONFIDENCE_WEIGHTS.get(confidence, 0.8)

        raw_score += severity_weight * confidence_weight

        if severity == "HIGH":
            high_count += 1
        elif severity == "MEDIUM":
            medium_count += 1

    # 仓库级额外风险修正
    if high_count >= 3:
        raw_score += 10
    if high_count >= 6:
        raw_score += 10
    if medium_count >= 5:
        raw_score += 5

    # 某些文件特别危险时，略微提高总分
    risky_files = 0
    for file_findings in file_groups.values():
        file_score = calculate_file_risk_score(file_findings)
        if file_score >= 20:
            risky_files += 1

    raw_score += risky_files * 3

    # 归一化到 0-100
    return min(100, int(round(raw_score)))


def group_findings_by_file(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group findings by file path.
    Compatible with either 'file_path' or legacy 'file'.
    """
    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for finding in findings:
        file_path = finding.get("file_path") or finding.get("file") or "unknown_file"
        grouped.setdefault(file_path, []).append(finding)

    return grouped


def get_top_risky_files(findings: List[Dict[str, Any]], top_n: int = 5) -> List[Dict[str, Any]]:
    """
    Return top risky files sorted by:
    1. file risk score desc
    2. findings count desc
    3. file path asc
    """
    grouped = group_findings_by_file(findings)
    ranked_files: List[Dict[str, Any]] = []

    for file_path, file_findings in grouped.items():
        risk_score = calculate_file_risk_score(file_findings)

        severity_counts = {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        for finding in file_findings:
            severity = str(finding.get("severity", "LOW")).upper()
            if severity in severity_counts:
                severity_counts[severity] += 1

        ranked_files.append(
            {
                "file_path": file_path,
                "risk_score": risk_score,
                "findings_count": len(file_findings),
                "severity_counts": severity_counts,
            }
        )

    ranked_files.sort(
        key=lambda item: (
            -item["risk_score"],
            -item["findings_count"],
            item["file_path"].lower(),
        )
    )

    return ranked_files[:top_n]


def summarize_severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        if severity in counts:
            counts[severity] += 1

    return counts


def build_risk_summary(findings: List[Dict[str, Any]], top_n: int = 5) -> Dict[str, Any]:
    """
    Build a reusable risk summary block for reports.
    """
    return {
        "severity_counts": summarize_severity_counts(findings),
        "repository_risk_score": calculate_repository_risk_score(findings),
        "top_risky_files": get_top_risky_files(findings, top_n=top_n),
    }

