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
    Enterprise SAST Core v3.0
    Features:
    - Global Class State Tracking (OOP support)
    - Type-Aware Sanitization (Reduces False Positives)
    - Hybrid Analysis (Taint + Regex Patterns)
    - Dict/List Taint Tracking
    """
    
    SOURCES = {
        # Flask
        'request.args.get': TaintSource('Flask GET', Severity.CRITICAL, 'URL'),
        'request.form.get': TaintSource('Flask POST', Severity.CRITICAL, 'Форма'),
        'request.json.get': TaintSource('Flask JSON', Severity.CRITICAL, 'JSON'),
        'request.cookies.get': TaintSource('Flask Cookie', Severity.HIGH, 'Cookie'),
        'request.headers.get': TaintSource('Flask Header', Severity.MEDIUM, 'Заголовки'),
        'request.values': TaintSource('Flask Values', Severity.CRITICAL, 'Values'),
        'request.get_json': TaintSource('Flask JSON Body', Severity.CRITICAL, 'JSON'),
        'request.files': TaintSource('Upload', Severity.HIGH, 'Загрузка файла'),
        
        # Django
        'request.GET.get': TaintSource('Django GET', Severity.CRITICAL, 'URL'),
        'request.POST.get': TaintSource('Django POST', Severity.CRITICAL, 'Форма'),
        'request.COOKIES.get': TaintSource('Django Cookie', Severity.HIGH, 'Cookie'),
        'request.META.get': TaintSource('Django META', Severity.MEDIUM, 'HTTP-заголовки'),
        'request.body': TaintSource('Django Body', Severity.CRITICAL, 'Body'),
        'request.FILES.get': TaintSource('Django File', Severity.HIGH, 'File'),
        
        # Django class-based views
        'self.request.GET.get': TaintSource('Django CBV GET', Severity.CRITICAL, 'URL'),
        'self.request.POST.get': TaintSource('Django CBV POST', Severity.CRITICAL, 'Форма'),
        'self.request.body': TaintSource('Django CBV Body', Severity.CRITICAL, 'Body'),
        'self.request.data.get': TaintSource('DRF CBV Data', Severity.CRITICAL, 'JSON'),
        
        # Django REST Framework
        'request.data.get': TaintSource('DRF JSON', Severity.CRITICAL, 'JSON'),
        'request.query_params.get': TaintSource('DRF Query', Severity.CRITICAL, 'URL'),
        'request.path_params.get': TaintSource('FastAPI Path', Severity.CRITICAL, 'Path'),
        
        # Django Forms
        'form.cleaned_data.get': TaintSource('Django Form', Severity.HIGH, 'Form'),
        'cleaned_data.get': TaintSource('Django Cleaned', Severity.HIGH, 'Form'),
        
        # kwargs / args
        'kwargs.get': TaintSource('kwargs', Severity.HIGH, 'kwargs'),
        'kwargs.__getitem__': TaintSource('kwargs[]', Severity.HIGH, 'kwargs'),
        'args.get': TaintSource('args', Severity.HIGH, 'args'),
        'args.__getitem__': TaintSource('args[]', Severity.HIGH, 'args'),
        
        # webargs / marshmallow
        'parser.parse': TaintSource('webargs', Severity.CRITICAL, 'webargs'),
        'parser.parse_args': TaintSource('webargs', Severity.CRITICAL, 'webargs'),
        'use_args': TaintSource('webargs decorator', Severity.CRITICAL, 'webargs'),
        
        # File System
        'os.path.join': TaintSource('Path Join', Severity.MEDIUM, 'Path'),
        'pathlib.Path': TaintSource('Path', Severity.MEDIUM, 'Path'),
        
        # Environment / CLI
        'getenv': TaintSource('Env', Severity.MEDIUM, 'Env'),
        'sys.argv': TaintSource('sys.argv', Severity.HIGH, 'Аргументы CLI'),
        'os.environ.get': TaintSource('Env', Severity.MEDIUM, 'Переменные окружения'),
        'os.getenv': TaintSource('Env', Severity.MEDIUM, 'Переменные окружения'),
        
        # Общие
        'input': TaintSource('stdin', Severity.CRITICAL, 'Консоль'),
        'open': TaintSource('File Read', Severity.HIGH, 'Файл'),

            # SQLAlchemy — опасные источники
        'session.query': TaintSource('SQLAlchemy Query', Severity.CRITICAL, 'ORM-запрос'),
        'select': TaintSource('SQLAlchemy Select', Severity.CRITICAL, 'ORM-запрос'),
        'text': TaintSource('SQLAlchemy Text', Severity.CRITICAL, 'Raw SQL'),
        
        # aiohttp
        'request.query': TaintSource('aiohttp Query', Severity.CRITICAL, 'URL'),
        'request.post': TaintSource('aiohttp POST', Severity.CRITICAL, 'Форма'),
        
        # Bottle
        'request.forms.get': TaintSource('Bottle Forms', Severity.CRITICAL, 'Форма'),
        'request.query.get': TaintSource('Bottle Query', Severity.CRITICAL, 'URL'),
        
        # Tornado
        'self.get_argument': TaintSource('Tornado Arg', Severity.CRITICAL, 'Аргумент'),
        'self.get_body_argument': TaintSource('Tornado Body', Severity.CRITICAL, 'Body'),
        'self.get_query_argument': TaintSource('Tornado Query', Severity.CRITICAL, 'URL'),
        
        # Pyramid
        'request.params.get': TaintSource('Pyramid Params', Severity.CRITICAL, 'Params'),
        'request.GET': TaintSource('Pyramid GET', Severity.CRITICAL, 'URL'),
        'request.POST': TaintSource('Pyramid POST', Severity.CRITICAL, 'Форма'),
        
        # Flask-RESTful
        'reqparse': TaintSource('Flask-RESTful', Severity.CRITICAL, 'Parser'),

        
    }
    
    SINKS = {
        # SQL
        'cursor.execute': TaintSink('SQL Injection', Severity.CRITICAL, 
            'Параметризованные запросы: cursor.execute(sql, params)', 'SQLi'),
        'cursor.executemany': TaintSink('SQL Injection', Severity.CRITICAL, 
            'Параметризованные запросы', 'SQLi'),
        'session.execute': TaintSink('SQL Injection', Severity.CRITICAL, 
            'Параметризация', 'SQLi'),
        'engine.execute': TaintSink('SQL Injection', Severity.CRITICAL, 
            'Параметризация', 'SQLi'),
        
        # OS commands
        'os.system': TaintSink('Command Injection', Severity.CRITICAL, 
            'subprocess.run([cmd], shell=False)', 'OS Command'),
        'os.popen': TaintSink('Command Injection', Severity.CRITICAL, 
            'subprocess.run([cmd], shell=False)', 'OS Command'),
        'subprocess.call': TaintSink('Command Injection', Severity.CRITICAL, 
            'subprocess.run([cmd], shell=False)', 'OS Command'),
        'subprocess.Popen': TaintSink('Command Injection', Severity.CRITICAL, 
            'subprocess.run([cmd], shell=False)', 'OS Command'),
        'subprocess.run': TaintSink('Command Injection', Severity.CRITICAL, 
            'shell=False + список аргументов', 'OS Command'),
        'os.execv': TaintSink('Command Injection', Severity.CRITICAL, 
            'subprocess', 'OS Command'),
        'os.execl': TaintSink('Command Injection', Severity.CRITICAL, 
            'subprocess', 'OS Command'),
        'os.execvp': TaintSink('Command Injection', Severity.CRITICAL, 
            'subprocess', 'OS Command'),
        'os.spawnv': TaintSink('Command Injection', Severity.CRITICAL, 
            'subprocess', 'OS Command'),
        
        # Code Exec
        'eval': TaintSink('Code Injection', Severity.CRITICAL, 
            'ast.literal_eval() или парсинг', 'Code Exec'),
        'exec': TaintSink('Code Injection', Severity.CRITICAL, 
            'Избегайте exec()', 'Code Exec'),
        '__import__': TaintSink('Dynamic Import', Severity.HIGH, 
            'Избегайте __import__', 'Code Exec'),
        
        # Deserialization
        'pickle.loads': TaintSink('Insecure Deserialization', Severity.HIGH, 
            'JSON + схема валидации', 'Deserialization'),
        'yaml.load': TaintSink('YAML Deserialization', Severity.HIGH, 
            'yaml.safe_load()', 'Deserialization'),
        'marshal.loads': TaintSink('Deserialization', Severity.HIGH, 
            'Не десериализуйте marshal', 'Deserialization'),
        'shelve.open': TaintSink('Deserialization', Severity.HIGH, 
            'Валидируйте данные', 'Deserialization'),
        'dill.loads': TaintSink('Deserialization', Severity.HIGH, 
            'Используйте JSON', 'Deserialization'),
        'cPickle.loads': TaintSink('Deserialization', Severity.HIGH, 
            'JSON', 'Deserialization'),
        
        # XSS / Templates
        'render_template': TaintSink('XSS', Severity.MEDIUM, 
            'Autoescaping в Jinja2', 'XSS'),
        'render_template_string': TaintSink('SSTI', Severity.CRITICAL, 
            'Не передавайте пользовательский ввод в шаблон', 'SSTI'),
        'render': TaintSink('XSS', Severity.MEDIUM, 
            'Автоэкранирование Django', 'XSS'),
        'render_to_response': TaintSink('XSS', Severity.MEDIUM, 
            'Автоэкранирование Django', 'XSS'),
        'mark_safe': TaintSink('XSS (опасная функция)', Severity.HIGH, 
            'mark_safe отключает защиту', 'XSS'),
        'Markup': TaintSink('XSS', Severity.MEDIUM, 
            'Не используйте Markup для пользовательских данных', 'XSS'),
        
        # SSRF
        'requests.get': TaintSink('SSRF', Severity.HIGH, 
            'Валидация URL + whitelist', 'SSRF'),
        'urllib.request.urlopen': TaintSink('SSRF', Severity.HIGH, 
            'Валидация URL + whitelist', 'SSRF'),
        
        # Path Traversal
        'open': TaintSink('Path Traversal', Severity.HIGH, 
            'os.path.realpath() + проверка пути', 'Path Traversal'),
        'read': TaintSink('Path Traversal', Severity.HIGH, 
            'os.path.realpath', 'Path Traversal'),
        'write': TaintSink('Path Traversal', Severity.HIGH, 
            'os.path.realpath', 'Path Traversal'),
        'os.makedirs': TaintSink('Path Traversal', Severity.MEDIUM, 
            'os.path.realpath', 'Path Traversal'),
        'os.remove': TaintSink('Path Traversal', Severity.HIGH, 
            'os.path.realpath', 'Path Traversal'),
        'os.unlink': TaintSink('Path Traversal', Severity.HIGH, 
            'os.path.realpath', 'Path Traversal'),
        'shutil.rmtree': TaintSink('Path Traversal', Severity.HIGH, 
            'os.path.realpath', 'Path Traversal'),
        
        # Crypto
        'hashlib.md5': TaintSink('Weak Crypto', Severity.MEDIUM, 
            'SHA-256', 'Crypto'),
        'hashlib.sha1': TaintSink('Weak Crypto', Severity.MEDIUM, 
            'SHA-256', 'Crypto'),

         # SQLAlchemy ORM
        'session.query': TaintSink('SQL Injection (ORM)', Severity.CRITICAL, 
            'Параметризация через filter', 'SQLi'),
        'session.add': TaintSink('SQL Injection (ORM)', Severity.MEDIUM, 
            'Валидация перед добавлением', 'SQLi'),
        'session.execute': TaintSink('SQL Injection', Severity.CRITICAL, 
            'Параметризация', 'SQLi'),
        
        # Django ORM
        'objects.extra': TaintSink('SQL Injection (ORM)', Severity.CRITICAL, 
            'Используйте filter', 'SQLi'),
        'objects.raw': TaintSink('SQL Injection (ORM)', Severity.CRITICAL, 
            'Используйте filter', 'SQLi'),
        'RawSQL': TaintSink('SQL Injection', Severity.CRITICAL, 
            'Параметризация', 'SQLi'),
        
        # aiohttp
        'aiohttp.ClientSession.get': TaintSink('SSRF', Severity.HIGH, 
            'Валидация URL', 'SSRF'),
        'aiohttp.ClientSession.post': TaintSink('SSRF', Severity.HIGH, 
            'Валидация URL', 'SSRF'),
        
        # Tornado
        'self.redirect': TaintSink('Open Redirect', Severity.MEDIUM, 
            'Валидация URL', 'Redirect'),
        
        # Общие
        'os.putenv': TaintSink('Command Injection', Severity.HIGH, 
            'Валидация', 'OS Command'),
        'os.spawnl': TaintSink('Command Injection', Severity.CRITICAL, 
            'subprocess', 'OS Command'),
        'os.spawnle': TaintSink('Command Injection', Severity.CRITICAL, 
            'subprocess', 'OS Command'),
    }
    
    TYPE_CAST_SANITIZERS = {
        'int', 'float', 'bool', 'list', 'dict', 'tuple', 'set'
    }
    # Санитайзеры для SSRF
    SSRF_SANITIZERS = {
        'urlparse', 'urlsplit', 'urljoin',
        'validators.url', 'validators.domain',
    }
    
    # Санитайзеры для Path Traversal
    PATH_SANITIZERS = {
        'os.path.basename', 'os.path.normpath',
        'werkzeug.utils.secure_filename',
        'django.utils._os.safe_join',
    }
    
    # Django-санитайзеры
    DJANGO_SANITIZERS = {
        'escape', 'conditional_escape', 'format_html',
        'strip_tags', 'json_script', 'urlquote',
        'django.utils.html.escape',
        'django.utils.html.conditional_escape',
        'django.utils.html.format_html',
    }
    
    # Шаблоны (Jinja2, Django) — автоэкранирование
    TEMPLATE_SANITIZERS = {
        'render_template',  # если autoescape=True (по умолчанию)
    }
    
    
    SAFE_ENCODING_SANITIZERS = {
        'html.escape', 'markupsafe.escape', 'shlex.quote',
        'urllib.parse.quote', 'json.dumps',
        'django.utils.html.escape', 'django.utils.html.format_html',
        'django.utils.html.json_script', 'django.utils.html.strip_tags',
        'django.utils.http.urlquote',
        're.escape', 'bleach.clean',
    }
    
    PATTERNS = [
        # Secrets
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', 
         'Hardcoded Password', Severity.HIGH, 'Secrets Management', 
         'Вынесите в .env или Vault'),
        (r'(?i)(api_key|apikey|token|secret)\s*=\s*["\'][^"\']+["\']', 
         'Hardcoded Secret/Key', Severity.CRITICAL, 'Secrets Management', 
         'Используйте переменные окружения'),
        (r'(?i)(secret_key|SECRET_KEY|jwt_secret)\s*=\s*["\'][^"\']{8,}["\']', 
         'Hardcoded Secret', Severity.CRITICAL, 'Secrets', 
         'Переменные окружения'),
        (r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][A-Z0-9]{16,}["\']', 
         'Hardcoded AWS Key', Severity.CRITICAL, 'Secrets', '.env'),
        (r'(?i)(private_key|PRIVATE_KEY)\s*=\s*["\']-----BEGIN', 
         'Hardcoded Private Key', Severity.CRITICAL, 'Secrets', 'Vault'),
        
        # Crypto
        (r'(?i)hashlib\.(md5|sha1)\s*\(', 'Weak Cryptographic Hash', 
         Severity.MEDIUM, 'Crypto', 'Используйте SHA-256'),
        (r'(?i)hashlib\.new\s*\(\s*["\'](md5|sha1)["\']', 
         'Weak Cryptographic Hash', Severity.MEDIUM, 'Crypto', 'SHA-256'),
        (r'(?i)random\.(random|randint|choice|shuffle)', 'Weak Randomness', 
         Severity.MEDIUM, 'Crypto', 'secrets module'),
        
        # Django Config
        (r'(?i)DEBUG\s*=\s*True', 'Django DEBUG=True', 
         Severity.HIGH, 'Config', 'DEBUG=False в продакшне'),
        (r'(?i)ALLOWED_HOSTS\s*=\s*\[\s*["\']\*["\']\s*\]', 
         'ALLOWED_HOSTS=*', Severity.HIGH, 'Config', 'Укажите домены'),
        (r'(?i)SECURE_SSL_REDIRECT\s*=\s*False', 
         'SSL Redirect отключён', Severity.HIGH, 'Config', 
         'SECURE_SSL_REDIRECT=True'),
        (r'(?i)CSRF_COOKIE_SECURE\s*=\s*False', 
         'CSRF Cookie не защищён', Severity.MEDIUM, 'Config', 
         'CSRF_COOKIE_SECURE=True'),
        (r'(?i)SESSION_COOKIE_SECURE\s*=\s*False', 
         'Session Cookie не защищён', Severity.MEDIUM, 'Config', 
         'SESSION_COOKIE_SECURE=True'),
        
        # Style
        (r'(?i)assert\s+', 'Assert в продакшне', 
         Severity.LOW, 'Style', 'Уберите assert'),
        (r'(?i)except\s*:\s*pass', 'Пустой except', 
         Severity.LOW, 'Style', 'Логируйте исключение'),

                # Django additional config
        (r'(?i)SECURE_HSTS_SECONDS\s*=\s*0', 'HSTS отключён', 
         Severity.MEDIUM, 'Config', 'SECURE_HSTS_SECONDS > 0'),
        (r'(?i)SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False', 
         'Nosniff отключён', Severity.MEDIUM, 'Config', 'True'),
        (r'(?i)CSRF_TRUSTED_ORIGINS\s*=\s*\[\s*["\']\*', 
         'CSRF Trusted=*', Severity.HIGH, 'Config', 'Укажите домены'),
        (r'(?i)PASSWORD_HASHERS\s*=\s*\[.*MD5', 
         'MD5 Password Hasher', Severity.HIGH, 'Crypto', 'PBKDF2'),
        
        # Python additional
        (r'(?i)os\.chmod\s*\(\s*[^,]+,\s*0o?777', 
         'chmod 777', Severity.HIGH, 'Config', 'Ограничьте права'),
        (r'(?i)tempfile\.mktemp', 'Устаревший mktemp', 
         Severity.MEDIUM, 'Crypto', 'tempfile.mkstemp'),
        (r'(?i)subprocess\.\w+\(.*shell\s*=\s*True', 
         'shell=True', Severity.HIGH, 'OS Command', 'shell=False'),
        
        # Flask
        (r'(?i)app\.run\s*\(.*debug\s*=\s*True', 'Flask DEBUG', 
         Severity.HIGH, 'Config', 'debug=False'),
    ]
    
    def __init__(self, code: str):
        self.code = code
        self.tainted: Dict[str, dict] = {}
        self.class_state: Dict[str, Dict[str, dict]] = defaultdict(dict)
        self.current_class: Optional[str] = None
        self.taint_chains: Dict[str, List[dict]] = defaultdict(list)
        self.vulnerabilities: List[Vulnerability] = []
        self.func_returns_taint: Dict[str, Set[str]] = defaultdict(set)
        # Карта функций: {func_name: {'params': [...], 'returns': [...], 'body': node}}
        self.functions: Dict[str, dict] = {}
        
        # Очередь вызовов для повторного анализа
        self.pending_calls: List[dict] = []
        
        # Множество функций, возвращающих taint
        self.functions_returning_taint: Set[str] = set()
        
        # Текущая функция
        self.current_function: Optional[str] = None
    
    def analyze(self) -> List[dict]:
        tree = ast.parse(self.code)
        return self.analyze_tree(tree)
    
    def analyze_tree(self, tree: ast.AST, source_code: str = None) -> List[dict]:
        """Двухпроходный анализ: сначала сбор функций, потом taint."""
        if source_code is not None:
            self.code = source_code
        
        # Проход 1: собираем все функции и их возвраты
        self.visit(tree)
        
        # Проход 2: если есть pending_calls — повторяем анализ
        # (taint передаётся через аргументы)
        if self.pending_calls:
            self.pending_calls = []  # сбрасываем, чтобы не зациклиться
            self.visit(tree)
        
        self._run_pattern_scan()
        return [v.__dict__ for v in self.vulnerabilities]
    
    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class

    def visit_Return(self, node: ast.Return):
        """Запоминаем, возвращает ли функция taint."""
        if node.value:
            t = self._get_taint_from_expr(node.value)
            if t and self.current_function:
                self.functions_returning_taint.add(self.current_function)
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Собирает информацию о функции: параметры, возвращаемое значение."""
        func_name = node.name
        params = [arg.arg for arg in node.args.args]
        
        self.functions[func_name] = {
            'params': params,
            'returns': [],
            'body': node,
            'node': node,
        }
        
        old_func = self.current_function
        self.current_function = func_name
        self.generic_visit(node)
        self.current_function = old_func
    
    def visit_Assign(self, node: ast.Assign):
        # 1. Проверка SOURCE
        if isinstance(node.value, ast.Call):
            func_name = self._resolve_call(node.value.func)
            if func_name in self.SOURCES:
                src = self.SOURCES[func_name]
                for target in node.targets:
                    self._mark_tainted(target, {
                        'source': func_name,
                        'line': node.lineno,
                        'name': src.name,
                        'severity': src.severity.value
                    })
                self.generic_visit(node)
                return
        
                # 2. Проверка SANITIZER (type-aware)
        sanitizer_cat = self._get_sanitizer_category(node.value)
        if sanitizer_cat:
            inner_taint = None
            if isinstance(node.value, ast.Call) and node.value.args:
                inner_taint = self._get_taint_from_expr(node.value.args[0])
            
            if inner_taint:
                taint_info = dict(inner_taint)
                taint_info['safe_for'] = sanitizer_cat  # ← категория
                for target in node.targets:
                    self._mark_tainted(target, taint_info)
            else:
                for target in node.targets:
                    self._mark_safe_for_os(target)
            
            self.generic_visit(node)
            return
        
        # 3. Распространение taint
        taint_info = self._get_taint_from_expr(node.value)
        if taint_info:
            for target in node.targets:
                self._mark_tainted(target, taint_info)
        
        self.generic_visit(node)
    
    def _mark_tainted(self, target_node: ast.AST, info: dict):
        """Маркировка Name, Attribute, Subscript."""
        if isinstance(target_node, ast.Name):
            self.tainted[target_node.id] = info
            self.taint_chains[target_node.id].append({
                "step": f"Tainted: {target_node.id}",
                "line": str(info['line'])
            })
        elif isinstance(target_node, ast.Attribute):
            if (isinstance(target_node.value, ast.Name) 
                and target_node.value.id == 'self' 
                and self.current_class):
                self.class_state[self.current_class][target_node.attr] = info
        elif isinstance(target_node, ast.Subscript):
            var_name = self._extract_var_name(target_node)
            if var_name:
                self.tainted[f"{var_name}.*"] = info
                if isinstance(target_node.slice, ast.Constant):
                    key = target_node.slice.value
                    self.tainted[f"{var_name}[{key}]"] = info
    
    def _mark_safe_for_os(self, target_node: ast.AST):
        """Помечает taint как safe для OS Command (int/float)."""
        if isinstance(target_node, ast.Name) and target_node.id in self.tainted:
            self.tainted[target_node.id]['safe_for_os'] = True
        elif isinstance(target_node, ast.Subscript):
            var_name = self._extract_var_name(target_node)
            if var_name and f"{var_name}.*" in self.tainted:
                self.tainted[f"{var_name}.*"]['safe_for_os'] = True
    
    def _remove_taint(self, target_node: ast.AST):
        """Полное удаление taint."""
        if isinstance(target_node, ast.Name) and target_node.id in self.tainted:
            del self.tainted[target_node.id]
        elif isinstance(target_node, ast.Attribute):
            if (isinstance(target_node.value, ast.Name) 
                and target_node.value.id == 'self' 
                and self.current_class):
                attr_name = target_node.attr
                if attr_name in self.class_state[self.current_class]:
                    del self.class_state[self.current_class][attr_name]
        elif isinstance(target_node, ast.Subscript):
            var_name = self._extract_var_name(target_node)
            if var_name:
                keys = [k for k in self.tainted 
                        if k.startswith(f"{var_name}[") or k == f"{var_name}.*"]
                for k in keys:
                    del self.tainted[k]
    
    def visit_Call(self, node: ast.Call):
        callee = self._resolve_call(node.func)
        if callee in self.SINKS:
            self._check_sink(node, callee, self.SINKS[callee])
        self.generic_visit(node)
    
    def _check_sink(self, call_node, sink_name, sink_info):
        """Проверка стока."""
        args = list(call_node.args) + [kw.value for kw in call_node.keywords]
        for arg in args:
            t = self._get_taint_from_expr(arg)
            if t:
                # Type-aware: пропускаем, если safe для этой категории
                safe_for = t.get('safe_for')
                if safe_for and safe_for == sink_info.category:
                    continue
                # Совместимость со старым safe_for_os
                if t.get('safe_for_os') and sink_info.category == 'OS Command':
                    continue
                
                var_name = self._extract_var_name(arg)
                chain = self.taint_chains.get(var_name, []) if var_name else []
                
                if not chain and self.current_class and var_name:
                    attr_info = self.class_state[self.current_class].get(var_name)
                    if attr_info:
                        chain = [{
                            "step": f"Class Attribute: {var_name}",
                            "line": str(attr_info['line'])
                        }]
                
                flow = (
                    [{"step": f"Source: {t['name']}", "line": str(t['line'])}]
                    + chain
                    + [{"step": f"Sink: {sink_name}", "line": str(call_node.lineno)}]
                )
                
                if not any(v.line == call_node.lineno and v.sink == sink_name
                           for v in self.vulnerabilities):
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
    
    def _get_param_taint(self, name: str) -> Optional[dict]:
        """Проверяет, не загрязнён ли параметр функции."""
        if self.current_function:
            key = f"{self.current_function}::{name}"
            if key in self.tainted:
                return self.tainted[key]
        return None

    def _get_taint_from_expr(self, node: ast.AST) -> Optional[dict]:
        if node is None:
            return None

        # 0. Параметр текущей функции
        if isinstance(node, ast.Name):
            param_taint = self._get_param_taint(node.id)
            if param_taint:
                return param_taint
        
        # 1. Переменная
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return self.tainted[node.id]
        
        # 2. Атрибут (self.attr или SOURCE)
        if isinstance(node, ast.Attribute):
            if (isinstance(node.value, ast.Name) 
                and node.value.id == 'self' 
                and self.current_class):
                attr_name = node.attr
                if attr_name in self.class_state[self.current_class]:
                    return self.class_state[self.current_class][attr_name]
            
            chain = self._resolve_call(node)
            if chain and chain in self.SOURCES:
                src = self.SOURCES[chain]
                return {
                    'source': chain,
                    'line': getattr(node, 'lineno', 0),
                    'name': src.name,
                    'severity': src.severity.value
                }
            
            return self._get_taint_from_expr(node.value)
        
        # 3. Конкатенация
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return (self._get_taint_from_expr(node.left) 
                    or self._get_taint_from_expr(node.right))
        
        # 4. F-strings
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t = self._get_taint_from_expr(v.value)
                    if t:
                        return t
        
        # 5. Subscript
        if isinstance(node, ast.Subscript):
            # a) request.GET['id']
            chain = self._resolve_call(node.value)
            if chain and chain in self.SOURCES:
                src = self.SOURCES[chain]
                return {
                    'source': chain,
                    'line': getattr(node, 'lineno', 0),
                    'name': src.name,
                    'severity': src.severity.value
                }
            
            # b) data['query']
            var_name = self._extract_var_name(node.value)
            if var_name and isinstance(node.slice, ast.Constant):
                key = node.slice.value
                exact = f"{var_name}[{key}]"
                if exact in self.tainted:
                    return self.tainted[exact]
            
            # c) data['any']
            if var_name and f"{var_name}.*" in self.tainted:
                return self.tainted[f"{var_name}.*"]
            
            return self._get_taint_from_expr(node.value)
        
                # 6. Вызов функции
        if isinstance(node, ast.Call):
            func_name = self._resolve_call(node.func)
            
            # a) Функция — SOURCE
            if func_name and func_name in self.SOURCES:
                src = self.SOURCES[func_name]
                return {
                    'source': func_name,
                    'line': getattr(node, 'lineno', 0),
                    'name': src.name,
                    'severity': src.severity.value
                }
            
            # b) Функция возвращает taint (call graph)
            if func_name and func_name in self.functions_returning_taint:
                return {
                    'source': f'function:{func_name}',
                    'line': getattr(node, 'lineno', 0),
                    'name': func_name,
                    'severity': 'high'
                }
            
            # c) Функция — известна, taint через аргументы
            if func_name and func_name in self.functions:
                func_info = self.functions[func_name]
                params = func_info['params']
                
                # Сопоставляем аргументы с параметрами
                for i, arg in enumerate(node.args):
                    if i < len(params):
                        t = self._get_taint_from_expr(arg)
                        if t:
                            # Помечаем параметр как загрязнённый
                            param_name = params[i]
                            # Записываем в taint_state с ключом func:param
                            self.tainted[f"{func_name}::{param_name}"] = t
                            
                            # Планируем повторный анализ тела функции
                            self.pending_calls.append({
                                'func': func_name,
                                'param': param_name,
                                'taint': t,
                            })
            
            # d) Рекурсивная проверка аргументов
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                t = self._get_taint_from_expr(arg)
                if t:
                    return t
        
        return None
    
    def _is_type_cast_sanitized(self, node: ast.AST) -> bool:
        """Проверяет, является ли выражение безопасным приведением типа."""
        if isinstance(node, ast.Call):
            func = self._resolve_call(node.func)
            return func in self.TYPE_CAST_SANITIZERS
        return False
    
    def _get_sanitizer_category(self, node: ast.AST) -> Optional[str]:
        """
        Возвращает категорию, для которой санитайзер снимает taint.
        None — если не санитайзер.
        """
        if not isinstance(node, ast.Call):
            return None
        
        func = self._resolve_call(node.func)
        
        if func in self.TYPE_CAST_SANITIZERS:
            return 'OS Command'  # int() защищает только от команд
        
        if func in self.SSRF_SANITIZERS:
            return 'SSRF'
        
        if func in self.PATH_SANITIZERS:
            return 'Path Traversal'
        
        if func in self.DJANGO_SANITIZERS:
            return 'XSS'
        
        return None
    
    def _run_pattern_scan(self):
        lines = self.code.split('\n')
        for pattern, name, severity, category, fix in self.PATTERNS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    self.vulnerabilities.append(Vulnerability(
                        name=name,
                        severity=severity.value,
                        line=i,
                        source="static_scan",
                        sink="pattern_match",
                        flow=[{"step": name, "line": str(i)}],
                        description=f"Обнаружен паттерн: {name}",
                        remediation=fix,
                        confidence=0.85,
                        category=category
                    ))
    
    def _extract_var_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == 'self':
                return node.attr
        if isinstance(node, ast.Subscript):
            return self._extract_var_name(node.value)
        return None
    
    def _resolve_call(self, func_node: ast.AST) -> Optional[str]:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            parts, cur = [], func_node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return '.'.join(reversed(parts))
        return None