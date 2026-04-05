from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass
class FunctionSymbol:
    """Top-level function in a module (V1: closures and nested call graph edges omitted)."""

    name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    is_async: bool


@dataclass
class FileSymbolMap:
    """Maps simple function names to AST nodes for same-file call resolution."""

    functions_by_name: dict[str, FunctionSymbol]

    def resolve_simple_call(self, name: str) -> FunctionSymbol | None:
        return self.functions_by_name.get(name)


def build_symbol_map(tree: ast.Module) -> FileSymbolMap:
    by_name: dict[str, FunctionSymbol] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            by_name[node.name] = FunctionSymbol(name=node.name, node=node, is_async=False)
        elif isinstance(node, ast.AsyncFunctionDef):
            by_name[node.name] = FunctionSymbol(name=node.name, node=node, is_async=True)
    return FileSymbolMap(functions_by_name=by_name)
