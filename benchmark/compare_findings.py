"""
Сравнение находок: наш vs Bandit vs Semgrep.
"""
import json
from pathlib import Path


def load_json(path):
    """Читает JSON с автоопределением кодировки."""
    raw = Path(path).read_bytes()
    for enc in ['utf-8', 'utf-8-sig', 'utf-16', 'cp1251', 'latin-1']:
        try:
            return json.loads(raw.decode(enc))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    raise ValueError(f'Не удалось прочитать {path}')


def parse_our(path):
    """Наш: {file: [findings]}"""
    data = load_json(path)
    result = set()
    for fpath, findings in data.items():
        for f in findings:
            clean = fpath.replace('..\\pygoat\\', '').replace('\\', '/')
            result.add((clean, f['line'], f['name']))
    return result


def parse_bandit(path):
    """Bandit: {results: [{filename, line_number, test_name}]}"""
    data = load_json(path)
    result = set()
    for r in data.get('results', []):
        clean = r['filename'].replace('..\\pygoat\\', '').replace('\\', '/')
        result.add((clean, r['line_number'], r['test_name']))
    return result


def parse_semgrep(path):
    """Semgrep: {results: [{path, start: {line}, check_id}]}"""
    data = load_json(path)
    result = set()
    for r in data.get('results', []):
        clean = r['path'].replace('..\\pygoat\\', '').replace('\\', '/')
        check = r['check_id'].split('.')[-1]
        result.add((clean, r['start']['line'], check))
    return result


def by_file(findings):
    """Группирует по файлам."""
    result = {}
    for fpath, line, name in findings:
        result.setdefault(fpath, []).append((line, name))
    return result


def main():
    base = Path('benchmark/results/pygoat')
    
    our = parse_our(base / 'our.json')
    bandit = parse_bandit(base / 'bandit.json')
    semgrep = parse_semgrep(base / 'semgrep.json')
    
    print('=' * 60)
    print('СРАВНЕНИЕ НАХОДОК')
    print('=' * 60)
    print(f'Наш:     {len(our)}')
    print(f'Bandit:  {len(bandit)}')
    print(f'Semgrep: {len(semgrep)}')
    print()
    
    # Уникальные
    our_files = {x[0] for x in our}
    bandit_files = {x[0] for x in bandit}
    semgrep_files = {x[0] for x in semgrep}
    
    print('Файлы с находками:')
    print(f'  Наш:     {len(our_files)}')
    print(f'  Bandit:  {len(bandit_files)}')
    print(f'  Semgrep: {len(semgrep_files)}')
    print()
    
    # Уникальные файлы — наш
    unique_our = our_files - bandit_files - semgrep_files
    print(f'Файлы, где нашли ТОЛЬКО МЫ: {len(unique_our)}')
    for f in sorted(unique_our):
        print(f'  {f}')
    print()
    
    # Уникальные файлы — Bandit
    unique_bandit = bandit_files - our_files - semgrep_files
    print(f'Файлы, где нашли ТОЛЬКО BANDIT: {len(unique_bandit)}')
    for f in sorted(unique_bandit):
        print(f'  {f}')


if __name__ == '__main__':
    main()