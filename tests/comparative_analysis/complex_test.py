import sqlite3
import os
import hashlib
from flask import request, render_template

class VulnerableApp:
    def __init__(self):
        # Тест 1: Hardcoded Secret (Должны найти все)
        self.api_key = "sk_live_12345_secret_key"

    def login(self):
        # Источник данных (Source)
        user_id = request.args.get('id')
        
        # Сохраняем в состояние класса (OOP State)
        self.current_user = user_id
        
        # Тест 2: Weak Crypto (Должны найти Bandit и мы)
        weak_hash = hashlib.md5(user_id.encode()).hexdigest()

    def get_profile(self):
        # Чтение из состояния класса (Межпроцедурный трекинг)
        # Bandit это ПРОПУСТИТ, так как не видит связи между методами
        query = f"SELECT * FROM users WHERE id='{self.current_user}'"
        
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        # Опасный вызов (Sink)
        cursor.execute(query) 

    def run_command(self):
        # Тест 3: Command Injection с санитайзером (Ложное срабатывание)
        port = request.args.get('port')
        
        # Санитайзер: приведение к int делает данные безопасными для os.system в контексте числа
        safe_port = int(port)
        
        # Bandit может заругаться на os.system, но умный анализатор должен понять, что safe_port - это int
        os.system(f"ping -c 1 127.0.0.1:{safe_port}")

    def render_page(self):
        # Тест 4: XSS через f-string
        name = request.form.get('name')
        return render_template(f"profile_{name}.html")