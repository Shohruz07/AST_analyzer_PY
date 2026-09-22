import hashlib
import pickle
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Set, List

CACHE_VERSION = "v1.0"


@dataclass
class AnalysisCache:
    version: str = CACHE_VERSION
    ast_cache: Dict[str, bytes] = field(default_factory=dict)
    class_state: Dict[str, Dict[str, dict]] = field(default_factory=dict)
    import_graph: Dict[str, Set[str]] = field(default_factory=dict)
    reverse_import_graph: Dict[str, Set[str]] = field(default_factory=dict)
    results: Dict[str, List[dict]] = field(default_factory=dict)
    file_hashes: Dict[str, str] = field(default_factory=dict)


class CacheManager:
    def __init__(self, cache_dir: Path):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "cache.pkl"
        self.cache = self._load()

    def _load(self) -> AnalysisCache:
        if not self.cache_file.exists():
            return AnalysisCache()
        try:
            with open(self.cache_file, 'rb') as f:
                cache = pickle.load(f)
            if getattr(cache, 'version', None) != CACHE_VERSION:
                print("[cache] Version mismatch, invalidating")
                return AnalysisCache()
            return cache
        except Exception as e:
            print(f"[cache] Corrupted, rebuilding: {e}")
            return AnalysisCache()

    def save(self):
        with open(self.cache_file, 'wb') as f:
            pickle.dump(self.cache, f)

    @staticmethod
    def file_hash(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def is_cached(self, path: Path) -> bool:
        key = str(path)
        if key not in self.cache.file_hashes:
            return False
        return self.cache.file_hashes[key] == self.file_hash(path)

    def get_ast(self, path: Path):
        key = str(path)
        content_hash = self.cache.file_hashes.get(key)
        if not content_hash:
            return None
        cached = self.cache.ast_cache.get(content_hash)
        if cached:
            return pickle.loads(cached)
        return None

    def put_ast(self, path: Path, tree, source: str):
        content_hash = self.file_hash(path)
        self.cache.file_hashes[str(path)] = content_hash
        self.cache.ast_cache[content_hash] = pickle.dumps(tree)

    def get_results(self, path: Path) -> List[dict]:
        return self.cache.results.get(str(path), [])

    def put_results(self, path: Path, findings: List[dict]):
        self.cache.results[str(path)] = findings

    def get_class_state(self) -> dict:
        return self.cache.class_state

    def put_class_state(self, state: dict):
        self.cache.class_state = state