WEAK_HASH_FUNCTIONS = {
    "hashlib.md5",
    "hashlib.sha1",
    "md5",
    "sha1",
}


def check_weak_hash_use(analyzer, node, func_name):
    if func_name in WEAK_HASH_FUNCTIONS:
        analyzer.add_finding(
            node,
            "WEAK_HASH_USE",
            "MEDIUM",
            f"Use of weak hash function {func_name}()",
        )
