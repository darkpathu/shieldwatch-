def calculate_verdict(clamav: dict, yara: dict, static: dict) -> dict:
    """
    Combines results from ClamAV, YARA, static analysis,
    and heuristic indicators to produce a final verdict.
    """

    score = 0
    reasons = []

    # 1️⃣ ClamAV — known malware
    if clamav.get("detected"):
        score += 70
        reasons.append("Known malware signature detected (ClamAV)")

    # 2️⃣ YARA — suspicious patterns
    if yara.get("matched"):
        score += 20
        reasons.append(f"YARA rule match: {', '.join(yara.get('rules', []))}")

    # 3️⃣ Entropy-based static signal
    if static.get("entropy", 0) > 7.2:
        score += 10
        reasons.append("High entropy indicates possible packing or obfuscation")

    # 4️⃣ Heuristic entropy logic
    heuristic = static.get("heuristic", {})
    score += heuristic.get("heuristic_score", 0)
    reasons.extend(heuristic.get("heuristic_reasons", []))

    # 5️⃣ Behavior-based zero-day logic
    behavior = static.get("behavior", {})
    score += behavior.get("behavior_score", 0)
    reasons.extend(behavior.get("behavior_reasons", []))

    # 6️⃣ Final verdict
    if score >= 70:
        verdict = "Malicious"
    elif score >= 40:
        verdict = "Suspicious (Potential Zero-Day)"
    else:
        verdict = "Clean"

    return {
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons
    }


