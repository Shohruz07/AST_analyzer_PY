import ast
from pathlib import Path
from typing import Dict, Set, List


class ImportGraphBuilder(ast.NodeVisitor):
    def __init__(self):
        self.imports: Set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self.imports.add(node.module)
        self.generic_visit(node)


class ImportGraph:
    def __init__(self, project_root: Path):
        self.root = Path(project_root)
        self.graph: Dict[str, Set[str]] = {}
        self.reverse: Dict[str, Set[str]] = {}

    def build(self, files: List[Path] = None):
        if files is None:
            files = [f for f in self.root.rglob("*.py")
                     if '.venv' not in str(f) and 'venv' not in str(f)
                     and '.ast_cache' not in str(f)]

        self.graph = {}
        self.reverse = {}

        for py_file in files:
            try:
                rel = str(py_file.relative_to(self.root))
                tree = ast.parse(py_file.read_text(encoding='utf-8'))
                b = ImportGraphBuilder()
                b.visit(tree)
                self.graph[rel] = b.imports
                for imp in b.imports:
                    self.reverse.setdefault(imp, set()).add(rel)
            except (SyntaxError, UnicodeDecodeError):
                continue
        return self.graph

    def file_to_module(self, file_path: str) -> str:
        return file_path.replace('\\', '/').replace('/', '.').replace('.py', '')

    def get_dependents(self, file_path: str) -> Set[str]:
        module = self.file_to_module(file_path)
        direct = self.reverse.get(module, set()).copy()
        # Также проверяем родительские модули (from app import x)
        parts = module.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[:i])
            direct.update(self.reverse.get(parent, set()))
        return direct

    def get_affected_files(self, changed: Set[str]) -> Set[str]:
        affected = set(changed)
        queue = list(changed)
        while queue:
            current = queue.pop()
            for dep in self.get_dependents(current):
                if dep not in affected:
                    affected.add(dep)
                    queue.append(dep)
        return affected