import subprocess
from pathlib import Path
from typing import Set, List


class DiffResolver:
    def __init__(self, project_root: Path):
        self.root = Path(project_root)

    def _git(self, args: List[str]) -> str:
        result = subprocess.run(
            ['git'] + args,
            capture_output=True, text=True, cwd=self.root
        )
        if result.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr}")
        return result.stdout

    def is_git_repo(self) -> bool:
        try:
            self._git(['rev-parse', '--git-dir'])
            return True
        except RuntimeError:
            return False

    def changed_files(self, base_ref: str = 'HEAD~1') -> Set[str]:
        output = self._git(['diff', '--name-only', base_ref, 'HEAD'])
        files = {f.strip() for f in output.split('\n') if f.strip()}
        return {f for f in files if f.endswith('.py')}

    def staged_files(self) -> Set[str]:
        output = self._git(['diff', '--cached', '--name-only'])
        files = {f.strip() for f in output.split('\n') if f.strip()}
        return {f for f in files if f.endswith('.py')}

    def uncommitted_files(self) -> Set[str]:
        output = self._git(['diff', '--name-only', 'HEAD'])
        files = {f.strip() for f in output.split('\n') if f.strip()}
        return {f for f in files if f.endswith('.py')}