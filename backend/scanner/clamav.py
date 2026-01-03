import subprocess

def scan_clamav(file_path: str):
    """
    Scans a file using the ClamAV antivirus engine.
    """

    result = subprocess.run(
        ["clamscan", file_path],
        capture_output=True,
        text=True
    )

    if "FOUND" in result.stdout:
        return {
            "detected": True,
            "engine": "ClamAV",
            "details": result.stdout.strip()
        }

    return {
        "detected": False,
        "engine": "ClamAV",
        "details": "No known malware signature found"
    }
