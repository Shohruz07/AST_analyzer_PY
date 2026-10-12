"""Проверка находок в Pygoat."""
import json

with open('benchmark/results/pygoat/our.json', encoding='utf-8') as f:
    data = json.load(f)

# 1. Файл broken_auth_lab
print('=== broken_auth_lab ===')
for path, findings in data.items():
    if 'broken_auth' in path:
        print(f'{path}: {len(findings)} находок')
        for f in findings:
            print(f'  [{f["severity"]}] {f["name"]} (стр. {f["line"]})')
print()

# 2. Crypto находки
print('=== Crypto находки ===')
for path, findings in data.items():
    for f in findings:
        cat = f.get('category', '')
        name = f.get('name', '')
        if 'Crypto' in cat or 'Crypto' in name:
            print(f'{path}: {name} (стр. {f["line"]})')
print()

# 3. Все категории
print('=== По категориям ===')
from collections import Counter
cats = Counter()
for path, findings in data.items():
    for f in findings:
        cats[f.get('category', 'Other')] += 1
for cat, count in cats.most_common():
    print(f'  {cat}: {count}')
print(f'Всего: {sum(cats.values())}')