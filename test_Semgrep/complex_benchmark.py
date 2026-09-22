import os
import sqlite3
import pickle
import yaml
import hashlib
from flask import request, render_template, session

## emgrep scan --config auto test_Semgrep/complex_benchmark.py
# semgrep scan --config p/owasp-top-ten test_Semgrep/complex_benchmark.py

class SecureApp:
    def __init__(self):
        # 1. SECRET: Hardcoded API Key (Bandit/Semgrep найдут)
        self.API_KEY = "sk_live_51Mz...secret_key_do_not_share"

    def process_user_data(self):
        """
        Сценарий 1: Межпроцедурная SQL Injection через состояние класса.
        Semgrep часто пропускает это, так как не видит связь между set_id и execute_query.
        """
        user_input = request.args.get('user_id')
        self._set_internal_state(user_input)
        return self._execute_query()

    def _set_internal_state(self, data):
        # Сохраняем tainted данные в атрибут класса
        self.db_filter = f"WHERE id = '{data}'"

    def _execute_query(self):
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        # Sink: Использование tainted self.db_filter
        # Bandit/Semgrep могут не увидеть источник здесь
        query = "SELECT * FROM users " + self.db_filter
        cursor.execute(query) 
        return cursor.fetchall()

    def run_system_command(self):
        """
        Сценарий 2: Command Injection с ложным санитайзером.
        Semgrep может ругаться на os.system, даже если аргумент приведен к int.
        Твой анализатор должен понять, что int() делает данные безопасными для CMDi.
        """
        port_str = request.form.get('port')
        # Санитайзер: приведение к целому числу
        safe_port = int(port_str)
        
        # Semgrep/Bandit часто дают FP (False Positive) здесь
        os.system(f"ping -c 1 127.0.0.1 -p {safe_port}")

    def load_config(self):
        """
        Сценарий 3: Insecure Deserialization (YAML/Pickle).
        Должны найти все.
        """
        raw_data = request.files['config'].read()
        
        # Опасно: yaml.load без SafeLoader
        config = yaml.load(raw_data, Loader=yaml.Loader)
        
        # Опасно: pickle.loads
        # session_data = pickle.loads(raw_data) 
        
        return config

    def render_profile(self):
        """
        Сценарий 4: XSS через f-string в шаблонизаторе.
        """
        username = request.cookies.get('username')
        # Прямая передача пользовательского ввода в имя шаблона
        return render_template(f"profiles/{username}.html")

    def weak_crypto_check(self):
        """
        Сценарий 5: Слабая криптография.
        Должны найти все.
        """
        password = request.form.get('password')
        # MD5 устарел и небезопасен
        return hashlib.md5(password.encode()).hexdigest()

# Инициализация приложения
app = SecureApp()