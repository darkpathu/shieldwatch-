import pefile
import math
from collections import Counter


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


def heuristic_analysis(entropy: float):
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

    return {
        "heuristic_score": score,
        "heuristic_reasons": reasons
    }


def static_analysis(file_path: str) -> dict:
    """
    Performs static analysis on a file.
    Extracts entropy, PE structure, and heuristic indicators.
    """

    results = {}

    # Read raw bytes ONCE
    with open(file_path, "rb") as f:
        data = f.read()

    # Entropy
    entropy = round(calculate_entropy(data), 2)
    results["entropy"] = entropy

    # Heuristic zero-day indicators
    results["heuristic"] = heuristic_analysis(entropy)

    # Try parsing as Windows PE file
    try:
        pe = pefile.PE(file_path)
        results["is_pe"] = True
        results["imports"] = len(pe.DIRECTORY_ENTRY_IMPORT)
        results["sections"] = len(pe.sections)
    except Exception:
        results["is_pe"] = False
        results["imports"] = 0
        results["sections"] = 0

    return results
