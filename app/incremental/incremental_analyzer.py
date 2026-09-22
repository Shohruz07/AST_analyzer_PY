import ast
import time
from pathlib import Path
from typing import Dict, List, Set

from app.analyzer import DataFlowAnalyzer
from app.incremental.cache import CacheManager
from app.incremental.import_graph import ImportGraph
from app.incremental.diff_resolver import DiffResolver


class IncrementalAnalyzer:
    def __init__(self, project_root: Path, cache_dir: Path = None):
        self.root = Path(project_root)
        self.cache_dir = Path(cache_dir) if cache_dir else (self.root / '.ast_cache')
        self.cache_mgr = CacheManager(self.cache_dir)
        self.import_graph = ImportGraph(self.root)
        self.diff_resolver = DiffResolver(self.root)

        self.stats = {
            'files_total': 0,
            'files_scanned': 0,
            'files_cached': 0,
            'ast_hits': 0,
            'ast_misses': 0,
            'time_total': 0.0,
        }

    def _iter_py_files(self) -> List[Path]:
        files = []
        for f in self.root.rglob('*.py'):
            s = str(f)
            if any(x in s for x in ['.venv', 'venv', '.ast_cache', '__pycache__', '.git']):
                continue
            files.append(f)
        return files

    # ----- FULL -----
    def analyze_full(self) -> Dict[str, List[dict]]:
        print("[full] Scanning entire project...")
        t0 = time.time()
        all_files = self._iter_py_files()

        self.import_graph.build(all_files)

        results = {}
        for f in all_files:
            results[str(f)] = self._scan_file(f, use_cache=False)

        self.stats['files_total'] = len(all_files)
        self.stats['files_scanned'] = len(all_files)
        self.stats['time_total'] = time.time() - t0

        for path, findings in results.items():
            self.cache_mgr.put_results(Path(path), findings)
        self.cache_mgr.save()
        return results

    # ----- INCREMENTAL -----
    def analyze_incremental(self, base_ref: str = 'HEAD~1') -> Dict[str, List[dict]]:
        print(f"[incremental] Diff vs {base_ref}...")
        t0 = time.time()

        if not self.diff_resolver.is_git_repo():
            print("[incremental] Not a git repo, falling back to full")
            return self.analyze_full()

        changed = self.diff_resolver.changed_files(base_ref)
        if not changed:
            print("[incremental] No changes")
            self.stats['time_total'] = time.time() - t0
            return self.cache_mgr.cache.results

        print(f"[incremental] Changed: {len(changed)} files")

        all_files = self._iter_py_files()
        self.import_graph.build(all_files)

        affected_rel = self.import_graph.get_affected_files(changed)
        affected_abs = {self.root / f for f in affected_rel}
        # фильтруем те, что не существуют (удалённые)
        affected_abs = {f for f in affected_abs if f.exists()}
        print(f"[incremental] Affected: {len(affected_abs)} files")

        results = dict(self.cache_mgr.cache.results)
        # Удалённые файлы убираем
        for k in list(results.keys()):
            if not Path(k).exists():
                del results[k]

        for f in affected_abs:
            results[str(f)] = self._scan_file(f, use_cache=True)

        self.stats['files_total'] = len(all_files)
        self.stats['files_scanned'] = len(affected_abs)
        self.stats['files_cached'] = len(all_files) - len(affected_abs)
        self.stats['time_total'] = time.time() - t0

        for path, findings in results.items():
            self.cache_mgr.put_results(Path(path), findings)
        self.cache_mgr.save()
        return results

    # ----- STAGED (pre-commit) -----
    def analyze_staged(self) -> Dict[str, List[dict]]:
        staged = self.diff_resolver.staged_files()
        print(f"[staged] {len(staged)} files")
        results = {}
        for f in staged:
            p = self.root / f
            if p.exists():
                results[f] = self._scan_file(p, use_cache=True)
        return results

    # ----- SINGLE FILE -----
    def _scan_file(self, py_file: Path, use_cache: bool = True) -> List[dict]:
        tree = None
        source = None

        if use_cache:
            tree = self.cache_mgr.get_ast(py_file)

        if tree is None:
            self.stats['ast_misses'] += 1
            try:
                source = py_file.read_text(encoding='utf-8')
                tree = ast.parse(source)
            except (SyntaxError, UnicodeDecodeError) as e:
                print(f"[scan] parse error {py_file}: {e}")
                return []
            if use_cache:
                self.cache_mgr.put_ast(py_file, tree, source)
        else:
            self.stats['ast_hits'] += 1
            try:
                source = py_file.read_text(encoding='utf-8')
            except Exception:
                source = ""

        analyzer = DataFlowAnalyzer(source or "")
        try:
            findings = analyzer.analyze_tree(tree, source_code=source)
        except Exception as e:
            print(f"[scan] analysis error {py_file}: {e}")
            return []
        return findings

    def print_stats(self):
        s = self.stats
        total = s['ast_hits'] + s['ast_misses']
        hit = (s['ast_hits'] / total * 100) if total else 0
        print("=" * 55)
        print("INCREMENTAL STATS")
        print("=" * 55)
        print(f"Total .py files:      {s['files_total']}")
        print(f"Scanned (affected):   {s['files_scanned']}")
        print(f"From cache:           {s['files_cached']}")
        print(f"AST cache hits:       {s['ast_hits']}")
        print(f"AST cache misses:     {s['ast_misses']}")
        print(f"Cache hit rate:       {hit:.1f}%")
        print(f"Time:                 {s['time_total']:.3f}s")
        print("=" * 55)