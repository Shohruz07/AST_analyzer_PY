from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/search")
def search():
    data = {}
    data['query'] = request.args.get("q")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name = '" + data['query'] + "'")
    return "OK"