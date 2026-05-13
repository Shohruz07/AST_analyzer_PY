import ast
import re
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional, Any
from enum import Enum
from dataclasses import dataclass, field

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class TaintSource:
    name: str
    severity: Severity
    description: str

@dataclass
class TaintSink:
    name: str
    severity: Severity
    remediation: str
    category: str = "Injection"

@dataclass
class Vulnerability:
    name: str
    severity: str
    line: int
    source: str
    sink: str
    flow: List[Dict[str, str]]
    description: str
    remediation: str
    confidence: float
    category: str = "Injection"

class DataFlowAnalyzer(ast.NodeVisitor):
    """
    Enterprise SAST Core v2.0
    Features:
    - Global Class State Tracking (OOP support)
    - Type-Aware Sanitization (Reduces False Positives)
    - Hybrid Analysis (Taint + Regex Patterns)
    """
    
    # --- DATABASES ---
    SOURCES = {
        'request.args.get': TaintSource('HTTP GET', Severity.CRITICAL, 'URL параметры'),
        'request.form.get': TaintSource('HTTP POST', Severity.CRITICAL, 'Форма'),
        'request.json.get': TaintSource('JSON Body', Severity.CRITICAL, 'JSON запрос'),
        'request.cookies.get': TaintSource('Cookie', Severity.HIGH, 'Куки'),
        'request.headers.get': TaintSource('Header', Severity.MEDIUM, 'Заголовки'),
        'input': TaintSource('stdin', Severity.CRITICAL, 'Консольный ввод'),
        'open': TaintSource('File Read', Severity.HIGH, 'Чтение файла'),
    }
    
    SINKS = {
        'cursor.execute': TaintSink('SQL Injection', Severity.CRITICAL, 'Параметризованные запросы: cursor.execute(sql, params)', 'SQLi'),
        'cursor.executemany': TaintSink('SQL Injection', Severity.CRITICAL, 'Параметризованные запросы', 'SQLi'),
        'os.system': TaintSink('Command Injection', Severity.CRITICAL, 'subprocess.run([cmd], shell=False)', 'OS Command'),
        'os.popen': TaintSink('Command Injection', Severity.CRITICAL, 'subprocess.run([cmd], shell=False)', 'OS Command'),
        'subprocess.call': TaintSink('Command Injection', Severity.CRITICAL, 'subprocess.run([cmd], shell=False)', 'OS Command'),
        'subprocess.Popen': TaintSink('Command Injection', Severity.CRITICAL, 'subprocess.run([cmd], shell=False)', 'OS Command'),
        'subprocess.run': TaintSink('Command Injection', Severity.CRITICAL, 'shell=False + список аргументов', 'OS Command'),
        'eval': TaintSink('Code Injection', Severity.CRITICAL, 'ast.literal_eval() или парсинг', 'Code Exec'),
        'exec': TaintSink('Code Injection', Severity.CRITICAL, 'Избегайте exec()', 'Code Exec'),
        'pickle.loads': TaintSink('Insecure Deserialization', Severity.HIGH, 'JSON + схема валидации', 'Deserialization'),
        'yaml.load': TaintSink('YAML Deserialization', Severity.HIGH, 'yaml.safe_load()', 'Deserialization'),
        'render_template': TaintSink('XSS', Severity.MEDIUM, 'Autoescaping в Jinja2', 'XSS'),
        'requests.get': TaintSink('SSRF', Severity.HIGH, 'Валидация URL + whitelist', 'SSRF'),
        'urllib.request.urlopen': TaintSink('SSRF', Severity.HIGH, 'Валидация URL + whitelist', 'SSRF'),
        'open': TaintSink('Path Traversal', Severity.HIGH, 'os.path.realpath() + проверка пути', 'Path Traversal'),
    }

    # Санитайзеры, меняющие ТИП данных (Приведение типов = Очистка от строковых атак)
    # int() превращает строку в число -> Command Injection невозможен (TypeError в runtime)
    TYPE_CAST_SANITIZERS = {'int', 'float', 'bool', 'list', 'dict', 'tuple', 'set'}
    
    # Санитайзеры, экранирующие данные (Безопасно для XSS/SQL, но опасно для Eval)
    SAFE_ENCODING_SANITIZERS = {'html.escape', 're.escape', 'shlex.quote', 'urllib.parse.quote', 'json.dumps'}

    PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', 'Hardcoded Password', Severity.HIGH, 'Secrets Management', 'Вынесите в .env или Vault'),
        (r'(?i)(api_key|apikey|token|secret)\s*=\s*["\'][^"\']+["\']', 'Hardcoded Secret/Key', Severity.CRITICAL, 'Secrets Management', 'Используйте переменные окружения'),
        (r'(?i)hashlib\.md5|hashlib\.sha1', 'Weak Cryptographic Hash', Severity.MEDIUM, 'Crypto', 'Используйте SHA-256 или bcrypt/argon2'),
        (r'(?i)random\.random|random\.randint', 'Weak Randomness', Severity.MEDIUM, 'Crypto', 'Для безопасности используйте secrets module'),
    ]

    def __init__(self, code: str):
        self.code = code
        self.tainted: Dict[str, dict] = {}  # Локальные переменные
        
        #  ENTERPRISE FEATURE: Глобальное состояние классов
        # Формат: { ClassName: { attr_name: taint_info } }
        self.class_state: Dict[str, Dict[str, dict]] = defaultdict(dict)
        self.current_class: Optional[str] = None
        
        self.taint_chains: Dict[str, List[dict]] = defaultdict(list)
        self.vulnerabilities: List[Vulnerability] = []
        self.func_returns_taint: Dict[str, Set[str]] = defaultdict(set)

    def analyze(self) -> List[dict]:
        tree = ast.parse(self.code)
        self.visit(tree)
        self._run_pattern_scan()
        return [v.__dict__ for v in self.vulnerabilities]

    def visit_ClassDef(self, node: ast.ClassDef):
        """Входим в класс — запоминаем его имя"""
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_func = self.current_class # Сохраняем контекст
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # 1️⃣ Проверка на SOURCE (Присваивание результата вызова)
        if isinstance(node.value, ast.Call):
            func_name = self._resolve_call(node.value.func)
            if func_name in self.SOURCES:
                src = self.SOURCES[func_name]
                for target in node.targets:
                    self._mark_tainted(target, {'source': func_name, 'line': node.lineno, 'name': src.name, 'severity': src.severity.value})
                self.generic_visit(node)
                return

        # 2️⃣ Проверка на SANITIZATION (Очистка)
        if self._is_type_cast_sanitized(node.value):
            # Если значение приведено к int/float — оно больше не опасно для командных инъекций
            for target in node.targets:
                self._remove_taint(target) # Удаляем метку тейнта
            self.generic_visit(node)
            return

        # 3️⃣ Распространение тейнта (Копирование)
        taint_info = self._get_taint_from_expr(node.value)
        if taint_info:
            for target in node.targets:
                self._mark_tainted(target, taint_info)
        
        self.generic_visit(node)

    def _mark_tainted(self, target_node: ast.AST, info: dict):
        """Умная маркировка: понимает и локальные переменные, и self.attr"""
        if isinstance(target_node, ast.Name):
            self.tainted[target_node.id] = info
            self.taint_chains[target_node.id].append({"step": f"Tainted: {target_node.id}", "line": str(info['line'])})
            
        elif isinstance(target_node, ast.Attribute):
            if isinstance(target_node.value, ast.Name) and target_node.value.id == 'self' and self.current_class:
                # Сохраняем в ГЛОБАЛЬНОЕ состояние класса
                self.class_state[self.current_class][target_node.attr] = info
                # print(f"[OOP STATE] Saved taint to {self.current_class}.{target_node.attr}")

    def _remove_taint(self, target_node: ast.AST):
        if isinstance(target_node, ast.Name) and target_node.id in self.tainted:
            del self.tainted[target_node.id]
        elif isinstance(target_node, ast.Attribute) and isinstance(target_node.value, ast.Name) and target_node.value.id == 'self' and self.current_class:
             attr_name = target_node.attr
             if attr_name in self.class_state[self.current_class]:
                 del self.class_state[self.current_class][attr_name]

    def visit_Call(self, node: ast.Call):
        callee = self._resolve_call(node.func)
        if callee in self.SINKS:
            self._check_sink(node, callee, self.SINKS[callee])
        self.generic_visit(node)

    def _check_sink(self, call_node: ast.Call, sink_name: str, sink_info: TaintSink):
        args = list(call_node.args) + [kw.value for kw in call_node.keywords]
        for arg in args:
            t = self._get_taint_from_expr(arg)
            if t:
                # Строим цепочку
                var_name = self._extract_var_name(arg)
                chain = self.taint_chains.get(var_name, [])
                # Если это self.attr, цепочка может быть пустой в локальном scope, берем из класса
                if not chain and self.current_class:
                     attr_info = self.class_state[self.current_class].get(var_name)
                     if attr_info:
                         chain = [{"step": f"Class Attribute: {var_name}", "line": str(attr_info['line'])}]

                flow = [{"step": f"Source: {t['name']}", "line": str(t['line'])}] + chain + [{"step": f"Sink: {sink_name}", "line": str(call_node.lineno)}]
                
                if not any(v.line == call_node.lineno and v.sink == sink_name for v in self.vulnerabilities):
                    self.vulnerabilities.append(Vulnerability(
                        name=f"{sink_info.name}",
                        severity=t.get('severity', sink_info.severity.value),
                        line=call_node.lineno,
                        source=t['source'],
                        sink=sink_name,
                        flow=flow,
                        description=f"Данные из '{t['name']}' попадают в {sink_name}",
                        remediation=sink_info.remediation,
                        confidence=0.95,
                        category=sink_info.category
                    ))

    def _get_taint_from_expr(self, node: ast.AST) -> Optional[dict]:
        if node is None: return None
        
        # 1. Прямая переменная
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return self.tainted[node.id]
            
        # 2. Атрибут класса (self.attr) -> ЭТО ГЛАВНОЕ УЛУЧШЕНИЕ
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == 'self' and self.current_class:
                attr_name = node.attr
                if attr_name in self.class_state[self.current_class]:
                    return self.class_state[self.current_class][attr_name]
            return self._get_taint_from_expr(node.value)

        # 3. Конкатенация
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._get_taint_from_expr(node.left) or self._get_taint_from_expr(node.right)
            
        # 4. F-strings
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t = self._get_taint_from_expr(v.value)
                    if t: return t
                    
        # 5. Dict Subscripts data['key']
        if isinstance(node, ast.Subscript):
            return self._get_taint_from_expr(node.value)
            
        return None

    def _is_type_cast_sanitized(self, node: ast.AST) -> bool:
        """Проверяет, является ли выражение безопасным приведением типа"""
        if isinstance(node, ast.Call):
            func = self._resolve_call(node.func)
            return func in self.TYPE_CAST_SANITIZERS
        return False

    def _run_pattern_scan(self):
        lines = self.code.split('\n')
        for pattern, name, severity, category, fix in self.PATTERNS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    self.vulnerabilities.append(Vulnerability(
                        name=name, severity=severity.value, line=i, source="static_scan",
                        sink="pattern_match", flow=[{"step": name, "line": str(i)}],
                        description=f"Обнаружен паттерн: {name}", remediation=fix,
                        confidence=0.85, category=category
                    ))

    def _extract_var_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'self':
            return node.attr
        if isinstance(node, ast.Subscript): return self._extract_var_name(node.value)
        return None

    def _resolve_call(self, func_node: ast.AST) -> Optional[str]:
        if isinstance(func_node, ast.Name): return func_node.id
        if isinstance(func_node, ast.Attribute):
            parts, cur = [], func_node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name): parts.append(cur.id)
            return '.'.join(reversed(parts))
        return None