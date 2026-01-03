def generate_ai_explanation(result: dict) -> str:
    verdict = result["final_verdict"]["verdict"]
    score = result["final_verdict"]["risk_score"]
    reasons = result["final_verdict"]["reasons"]

    if verdict.lower() == "malicious":
        explanation = (
            "This file has been classified as malicious based on multiple detection engines. "
            "The scan identified known malware signatures and suspicious characteristics "
            "commonly associated with harmful software."
        )
    elif verdict.lower() == "suspicious":
        explanation = (
            "This file exhibits suspicious characteristics that deviate from typical benign files. "
            "Although no known malware signature was detected, heuristic analysis suggests "
            "potential risk."
        )
    else:
        explanation = (
            "This file appears to be safe. No known malware signatures or suspicious patterns "
            "were detected during the analysis."
        )

    if score > 70:
        explanation += " The high risk score indicates a strong likelihood of malicious behavior."
    elif score > 30:
        explanation += " The moderate risk score suggests caution before using this file."

    return explanation
