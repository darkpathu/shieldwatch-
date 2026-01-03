import pefile
import math
from collections import Counter


SUSPICIOUS_APIS = {
    "VirtualAlloc",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
}


def calculate_entropy(data: bytes) -> float:
    """
    Calculates Shannon entropy of file bytes.
    High entropy often indicates packing or encryption.
    """
    if not data:
        return 0.0

    entropy = 0.0
    counts = Counter(data)

    for count in counts.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)

    return entropy


def heuristic_analysis(entropy: float) -> dict:
    """
    Heuristic-based analysis for potential zero-day threats.
    """
    score = 0
    reasons = []

    if entropy > 7.5:
        score += 40
        reasons.append("High entropy suggests packed or encrypted content")
    elif entropy > 6.8:
        score += 20
        reasons.append("Moderately high entropy indicates obfuscation")
    elif score >= 40:
        verdict = "Suspicious (Potential Zero-Day)"

    return {
        "heuristic_score": score,
        "heuristic_reasons": reasons,
    }


def behavior_analysis(pe) -> dict:
    """
    Behavior-based static analysis using suspicious Windows API imports.
    """
    score = 0
    reasons = []

    try:
        imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode(errors="ignore"))

        suspicious_used = SUSPICIOUS_APIS.intersection(set(imports))

        if suspicious_used:
            score += 30
            reasons.append(
                f"Suspicious Windows API usage: {', '.join(suspicious_used)}"
            )

    except Exception:
        pass

    return {
        "behavior_score": score,
        "behavior_reasons": reasons,
    }


def static_analysis(file_path: str) -> dict:
    """
    Performs static analysis on a file.
    Extracts entropy, PE structure, heuristics, and behavior indicators.
    """
    results = {}

    # Read raw bytes once
    with open(file_path, "rb") as f:
        data = f.read()

    # Entropy
    entropy = round(calculate_entropy(data), 2)
    results["entropy"] = entropy

    # Heuristic zero-day indicators
    results["heuristic"] = heuristic_analysis(entropy)

    # PE + behavior analysis
    try:
        pe = pefile.PE(file_path)
        results["is_pe"] = True
        results["imports"] = len(pe.DIRECTORY_ENTRY_IMPORT)
        results["sections"] = len(pe.sections)

        # ✅ CONNECT behavior analysis
        results["behavior"] = behavior_analysis(pe)

    except Exception:
        results["is_pe"] = False
        results["imports"] = 0
        results["sections"] = 0
        results["behavior"] = {
            "behavior_score": 0,
            "behavior_reasons": [],
        }

    return results
