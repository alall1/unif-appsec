def check_eval_use(analyzer, node, func_name):
    if func_name == "eval":
        analyzer.add_finding(
            node,
            "EVAL_USE",
            "HIGH",
            "Use of eval() is dangerous",
        )


def check_exec_use(analyzer, node, func_name):
    if func_name == "exec":
        analyzer.add_finding(
            node,
            "EXEC_USE",
            "HIGH",
            "Use of exec() is dangerous",
        )


def check_os_system_use(analyzer, node, func_name):
    if func_name == "os.system":
        analyzer.add_finding(
            node,
            "OS_SYSTEM_USE",
            "MEDIUM",
            "Use of os.system() can be dangerous",
        )


def check_command_injection(analyzer, node, func_name):
    if func_name == "os.system":
        if node.args and analyzer.is_tainted_name(node.args[0]):
            analyzer.add_finding(
                node,
                "COMMAND_INJECTION",
                "CRITICAL",
                "Tainted input reaches os.system()",
            )


def check_subprocess_rules(analyzer, node, func_name):
    if func_name in analyzer.SUBPROCESS_FUNCTIONS:
        if analyzer.has_shell_true(node):
            analyzer.add_finding(
                node,
                "SUBPROCESS_SHELL_TRUE",
                "HIGH",
                f"Use of {func_name} with shell=True can be dangerous",
            )

        if node.args and analyzer.is_tainted_name(node.args[0]):
            analyzer.add_finding(
                node,
                "TAINTED_SUBPROCESS_INPUT",
                "HIGH",
                f"Tainted input reaches {func_name}()",
            )
