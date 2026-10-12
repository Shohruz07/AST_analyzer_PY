from flask import Flask, request
import sqlite3

app = Flask(__name__)

def get_user(user_id):
    # Taint приходит через аргумент
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchall()

@app.route("/user")
def user_view():
    uid = request.args.get("id")
    return str(get_user(uid))