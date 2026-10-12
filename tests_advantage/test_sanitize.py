from flask import Flask, request
import os
import sqlite3

app = Flask(__name__)

@app.route("/run")
def run():
    # Type cast — снимает taint для OS Command
    user_id = int(request.args.get("id"))
    
    # БЕЗОПАСНО для OS Command — int не пропустит строку
    os.system(f"echo {user_id}")
    
    # ОПАСНО для SQL — int не защищает от SQLi в конкатенации
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")