import ast

from minisast.finding import Finding
from minisast.rules.crypto import check_weak_hash_use
from minisast.rules.dangerous_calls import (
    check_command_injection,
    check_eval_use,
    check_exec_use,
    check_os_system_use,
    check_subprocess_rules,
)
from minisast.rules.secrets import check_hardcoded_secret


class Analyzer(ast.NodeVisitor):
    SUBPROCESS_FUNCTIONS = {
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
    }

    def __init__(self, file_path):
        self.file_path = str(file_path)
        self.findings = []
        self.tainted_vars = set()

    def analyze(self, tree):
        self.visit(tree)
        return self.findings

    def add_finding(self, node, rule_id, severity, message):
        self.findings.append(
            Finding(
                file=self.file_path,
                line=getattr(node, "lineno", 0),
                rule_id=rule_id,
                severity=severity,
                message=message,
            )
        )

    def get_full_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self.get_full_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return None

    def is_string_literal(self, node):
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    def is_tainted_name(self, node):
        return isinstance(node, ast.Name) and node.id in self.tainted_vars

    def has_shell_true(self, node):
        for kw in node.keywords:
            if kw.arg == "shell":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
        return False

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call):
            func_name = self.get_full_name(node.value.func)
            if func_name == "input":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        if isinstance(node.value, ast.Name) and node.value.id in self.tainted_vars:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)

        check_hardcoded_secret(self, node)

        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = self.get_full_name(node.func)

        check_eval_use(self, node, func_name)
        check_exec_use(self, node, func_name)
        check_os_system_use(self, node, func_name)
        check_command_injection(self, node, func_name)
        check_subprocess_rules(self, node, func_name)
        check_weak_hash_use(self, node, func_name)

        self.generic_visit(node)
