import yara

# Compile YARA rules once at startup
rules = yara.compile(filepath="rules/basic.yar")

def scan_yara(file_path: str):
    """
    Scans a file using YARA rules.
    """

    matches = rules.match(file_path)

    return {
        "matched": len(matches) > 0,
        "rules": [match.rule for match in matches]
    }
