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

    # 4️⃣ 🔹 Zero-day heuristic logic (NEW)
    heuristic = static.get("heuristic", {})
    heuristic_score = heuristic.get("heuristic_score", 0)

    if heuristic_score > 0 and not clamav.get("detected"):
        score += heuristic_score
        reasons.extend(heuristic.get("heuristic_reasons", []))

    # 5️⃣ Final verdict decision
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

