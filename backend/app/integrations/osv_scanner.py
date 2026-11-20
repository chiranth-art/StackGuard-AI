import httpx

OSV_API_URL = "https://api.osv.dev/v1/query"


async def scan_package(package_name: str, version: str) -> dict:
    """
    Check a specific Python package version against OSV.
    """

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": version
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(
                OSV_API_URL,
                json=payload
            )

            response.raise_for_status()
            data = response.json()

        vulnerabilities = data.get("vulns", [])

        results = []

        for vuln in vulnerabilities:
            severity = "UNKNOWN"

            # Extract CVSS severity if available
            for item in vuln.get("severity", []):
                if item.get("type", "").upper().startswith("CVSS"):
                    severity = item.get("score", "UNKNOWN")
                    break

            results.append({
                "id": vuln.get("id"),
                "summary": vuln.get("summary", "No summary available"),
                "severity": severity,
                "modified": vuln.get("modified"),
                "references": [
                    ref.get("url")
                    for ref in vuln.get("references", [])
                    if ref.get("url")
                ]
            })

        return {
            "package": package_name,
            "version": version,
            "vulnerable": len(results) > 0,
            "vulnerability_count": len(results),
            "vulnerabilities": results
        }

    except httpx.HTTPError as exc:
        return {
            "package": package_name,
            "version": version,
            "error": str(exc),
            "vulnerable": None,
            "vulnerability_count": None,
            "vulnerabilities": []
        }