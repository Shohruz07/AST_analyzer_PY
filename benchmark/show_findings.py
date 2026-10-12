def show_our_analyzer(data):
    """Наш формат: {file: [findings]}"""
    total = sum(len(v) for v in data.values())
    print(f'=== Всего находок: {total} ===')
    print()
    
    # По категориям
    by_category = {}
    for path, findings in data.items():
        for f in findings:
            cat = f.get('category', 'Other')
            by_category.setdefault(cat, 0)
            by_category[cat] += 1
    
    print('--- По категориям ---')
    for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
        print(f'  {cat}: {count}')
    print()
    
    # Детально с путями
    print('--- Детальный список ---')
    for path, findings in data.items():
        if not findings:
            continue
        print()
        print(f'>>> {path}')
        for f in findings:
            sev = f.get('severity', '?')
            name = f.get('name', '?')
            line = f.get('line', '?')
            print(f'  [{sev}] {name} (стр. {line})')
            
            # Путь данных
            flow = f.get('flow', [])
            if flow:
                path_str = ' → '.join(
                    f'{step["step"]} (стр. {step["line"]})' 
                    for step in flow
                )
                print(f'      Путь: {path_str}')
            
            # Рекомендация
            rem = f.get('remediation', '')
            if rem:
                print(f'      Рекомендация: {rem}')