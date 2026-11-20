
from app.analyzers.dependency_parser import parse_requirements
from app.integrations.osv_scanner import scan_package
from app.analyzers.risk_engine import calculate_risk


async def scan_requirements(content: str) -> dict:
    """
    Scan dependencies from requirements.txt
    """

    # Step 1: Parse the requirements file
    dependencies = parse_requirements(content)

    results = []

    # Step 2: Process each dependency
    for dependency in dependencies:

        name = dependency["name"]
        version = dependency["version"]

        # Packages without exact versions cannot be reliably scanned
        if not dependency["is_exact"] or not version:

            results.append({
                **dependency,
                "scan_status": "SKIPPED_VERSION_NOT_EXACT",
                "vulnerable": None,
                "vulnerability_count": None,
                "vulnerabilities": [],
                "risk": {
                    "risk_score": None,
                    "risk_level": "UNKNOWN",
                    "reason": "Exact package version required for scanning"
                }
            })

            continue

        # Step 3: Scan package using OSV
        scan_result = await scan_package(name, version)

        # Step 4: Calculate risk
        risk = calculate_risk(scan_result)

        # Step 5: Store final package result
        results.append({
            **dependency,
            "scan_status": (
                "FAILED" if scan_result.get("error") else "COMPLETED"
            ),
            "vulnerable": scan_result.get("vulnerable"),
            "vulnerability_count": scan_result.get(
                "vulnerability_count"
            ),
            "vulnerabilities": scan_result.get(
                "vulnerabilities", []
            ),
            "risk": risk
        })

    # Step 6: Calculate project summary
    successfully_scanned = [
        package for package in results
        if package["scan_status"] == "COMPLETED"
    ]

    vulnerable_packages = [
        package for package in successfully_scanned
        if package["vulnerable"]
    ]

    total_vulnerabilities = sum(
        package["vulnerability_count"] or 0
        for package in successfully_scanned
    )

    scores = [
        package["risk"]["risk_score"]
        for package in successfully_scanned
        if package["risk"]["risk_score"] is not None
    ]

    # Highest package risk represents project risk
    if scores:
        project_risk_score = max(scores)

        if project_risk_score >= 80:
            project_risk_level = "CRITICAL"
        elif project_risk_score >= 60:
            project_risk_level = "HIGH"
        elif project_risk_score >= 30:
            project_risk_level = "MODERATE"
        elif project_risk_score > 0:
            project_risk_level = "LOW"
        else:
            project_risk_level = "SAFE"

    else:
        project_risk_score = None
        project_risk_level = "UNKNOWN"

    return {
        "project_summary": {
            "total_dependencies": len(dependencies),
            "scanned_dependencies": len(successfully_scanned),
            "skipped_dependencies": sum(
                1 for package in results
                if package["scan_status"]
                == "SKIPPED_VERSION_NOT_EXACT"
            ),
            "failed_scans": sum(
                1 for package in results
                if package["scan_status"] == "FAILED"
            ),
            "vulnerable_packages": len(vulnerable_packages),
            "total_vulnerabilities": total_vulnerabilities,
            "project_risk_score": project_risk_score,
            "project_risk_level": project_risk_level
        },
        "dependencies": results
    }
