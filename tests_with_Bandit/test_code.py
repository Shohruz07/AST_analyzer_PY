from flask import request
import sqlite3
import os
import pickle

def sql_injection():
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

def command_injection():
    filename = request.args.get('file')
    os.system(f"cat {filename}")

def code_injection():
    expression = request.args.get('expr')
    eval(expression)

def deserialization():
    data = request.args.get('data')
    obj = pickle.loads(data)

def safe():
    user_id = request.args.get('id')
    safe_id = int(user_id)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (safe_id,))