import random

SEVERITY_TO_CVSS = {
    "LOW": (0.1, 3.9),
    "MEDIUM": (4.0, 6.9),
    "HIGH": (7.0, 8.9),
    "CRITICAL": (9.0, 10.0)
}

def severity_to_cvss(severity: str) -> float:
    low, high = SEVERITY_TO_CVSS.get(severity, (4.0, 6.9))
    return round(random.uniform(low, high), 1)

def cvss_to_risk(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical Risk"
    elif cvss >= 7.0:
        return "High Risk"
    elif cvss >= 4.0:
        return "Medium Risk"
    else:
        return "Low Risk"