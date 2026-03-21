SUSPICIOUS_SECRET_NAMES = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
}


def check_hardcoded_secret(analyzer, node):
    if analyzer.is_string_literal(node.value):
        for target in node.targets:
            if hasattr(target, "id"):
                if target.id.lower() in SUSPICIOUS_SECRET_NAMES:
                    analyzer.add_finding(
                        node,
                        "HARDCODED_SECRET",
                        "HIGH",
                        f"Possible hardcoded secret assigned to '{target.id}'",
                    )
