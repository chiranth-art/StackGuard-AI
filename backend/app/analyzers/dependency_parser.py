import re


def parse_requirements(content: str) -> list[dict]:
    dependencies = []

    for line in content.splitlines():

        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Skip unsupported entries for now
        if line.startswith(("-", "http://", "https://", "git+")):
            continue

        # Remove inline comments
        line = line.split("#", 1)[0].strip()

        # Remove environment markers
        if ";" in line:
            line = line.split(";", 1)[0].strip()

        # Extract package name and optional extras
        match = re.match(
            r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$",
            line
        )

        if not match:
            continue

        package_name = match.group(1).lower()
        version_constraint = match.group(2).strip()

        operator = None
        version = None
        is_exact = False

        # Extract version operator and version number
        version_match = re.match(
            r"^(===|==|~=|!=|>=|<=|>|<)\s*(.+)$",
            version_constraint
        )

        if version_match:
            operator = version_match.group(1)
            version = version_match.group(2).strip()

            # Only == with a specific version is considered exact
            if operator == "==" and not any(
                symbol in version for symbol in ["*", ","]
            ):
                is_exact = True

        dependencies.append({
            "name": package_name,
            "operator": operator,
            "version": version,
            "version_constraint": version_constraint or "unspecified",
            "is_exact": is_exact
        })

    return dependencies