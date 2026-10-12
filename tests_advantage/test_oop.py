from flask import Flask, request
import sqlite3

app = Flask(__name__)

class UserService:
    def __init__(self):
        self.connection = sqlite3.connect("users.db")
        self.user_id = None
    
    def login(self):
        # Источник в методе 1
        self.user_id = request.args.get("id")
    
    def get_profile(self):
        # Сток в методе 2 через self
        cursor = self.connection.cursor()
        query = f"SELECT * FROM users WHERE id = '{self.user_id}'"
        cursor.execute(query)
        return cursor.fetchall()

@app.route("/profile")
def profile():
    service = UserService()
    service.login()
    return str(service.get_profile())