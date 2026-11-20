def calculate_risk(scan_result: dict) -> dict:
    """
    Calculate a vulnerability-based risk score from OSV results.

    Risk score: 0-100
    """

    if scan_result.get("error"):
        return {
            "risk_score": None,
            "risk_level": "UNKNOWN",
            "reason": "Vulnerability scan failed"
        }

    vulnerabilities = scan_result.get("vulnerabilities", [])

    # No known vulnerabilities found
    if not vulnerabilities:
        return {
            "risk_score": 0,
            "risk_level": "SAFE",
            "reason": "No known vulnerabilities detected"
        }

    # Collect available CVSS scores (typically 0-10)
    cvss_scores = []

    for vulnerability in vulnerabilities:
        severity = vulnerability.get("severity", "UNKNOWN")

        try:
            score = float(severity)

            if 0 <= score <= 10:
                cvss_scores.append(score)

        except (ValueError, TypeError):
            continue

    # Calculate score
    if cvss_scores:
        highest_cvss = max(cvss_scores)

        # Convert CVSS to a 100-point scale
        base_score = highest_cvss * 10

        # Increase risk slightly for multiple vulnerabilities
        additional_risk = (len(vulnerabilities) - 1) * 5

        risk_score = min(100, round(base_score + additional_risk))

    else:
        # Fallback when CVSS data is missing
        risk_score = min(100, 30 + (len(vulnerabilities) - 1) * 10)

    # Determine risk level
    if risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MODERATE"
    else:
        risk_level = "LOW"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reason": f"{len(vulnerabilities)} known vulnerability(s) detected"
    }