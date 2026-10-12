"""
Сравнение результатов анализаторов на bench_project.
"""
import json
from pathlib import Path
from collections import defaultdict

def load_results(path):
    """Читает JSON с автоопределением кодировки."""
    raw = path.read_bytes()
    
    # UTF-16 с BOM (LE или BE) — Python сам определит
    if raw.startswith(b'\xff\xfe') or raw.startswith(b'\xfe\xff'):
        return json.loads(raw.decode('utf-16'))
    
    # UTF-8 с BOM
    if raw.startswith(b'\xef\xbb\xbf'):
        return json.loads(raw.decode('utf-8-sig'))
    
    # Без BOM — UTF-8
    return json.loads(raw.decode('utf-8'))


def count_our(data):
    """Наш анализатор: {file: [findings]}"""
    total = sum(len(v) for v in data.values())
    return total


def count_bandit(data):
    """Bandit: {results: [...]}"""
    return len(data.get('results', []))


def count_semgrep(data):
    """Semgrep: {results: [...]}"""
    return len(data.get('results', []))


def count_pylint(data):
    """Pylint: [ {type, ...} ]"""
    security = [x for x in data if x.get('type') == 'error']
    return len(security)


def main():
    base = Path(__file__).parent / 'results'
    
    results = {
        'Наш анализатор': count_our(load_results(base / 'results_our.json')),
        'Bandit': count_bandit(load_results(base / 'results_bandit.json')),
        'Semgrep OSS': count_semgrep(load_results(base / 'results_semgrep.json')),
        'Pylint': count_pylint(load_results(base / 'results_pylint.json')),
    }
    
    print("=" * 50)
    print("СРАВНЕНИЕ АНАЛИЗАТОРОВ")
    print("=" * 50)
    print(f"{'Инструмент':<20} {'Найдено':<10}")
    print("-" * 50)
    for name, count in results.items():
        print(f"{name:<20} {count:<10}")
    print("=" * 50)


if __name__ == '__main__':
    main()