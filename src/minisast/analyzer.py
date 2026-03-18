import ast

from minisast.finding import Finding


class Analyzer(ast.NodeVisitor):
    SUSPICIOUS_SECRET_NAMES = {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
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

        if self.is_string_literal(node.value):
            value = node.value.value
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if target.id.lower() in self.SUSPICIOUS_SECRET_NAMES:
                        self.add_finding(
                            node,
                            "HARDCODED_SECRET",
                            "HIGH",
                            f"Possible hardcoded secret assigned to '{target.id}'",
                        )

        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = self.get_full_name(node.func)

        if func_name == "eval":
            self.add_finding(
                node,
                "EVAL_USE",
                "HIGH",
                "Use of eval() is dangerous",
            )

        if func_name == "exec":
            self.add_finding(
                node,
                "EXEC_USE",
                "HIGH",
                "Use of exec() is dangerous",
            )

        if func_name == "os.system":
            if node.args and self.is_tainted_name(node.args[0]):
                self.add_finding(
                    node,
                    "COMMAND_INJECTION",
                    "CRITICAL",
                    "Tainted input reaches os.system()",
                )
            else:
                self.add_finding(
                    node,
                    "OS_SYSTEM_USE",
                    "MEDIUM",
                    "Use of os.system() can be dangerous",
                )

        self.generic_visit(node)
