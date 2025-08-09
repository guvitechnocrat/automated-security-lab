from flask import Flask, request, jsonify
import sqlite3, html

app = Flask(__name__)

# Simple in-memory DB
def get_db():
    conn = sqlite3.connect(':memory:')
    conn.execute('CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT)')
    conn.execute("INSERT INTO items (name) VALUES ('item1')")
    return conn

# Vulnerable SQL endpoint (SQLi)
@app.route('/user')
def user():
    username = request.args.get('username','')
    conn = get_db()
    cursor = conn.cursor()
    # Vulnerable pattern (string formatting) — intentional for DAST
    query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
    except Exception as e:
        rows = []
    return jsonify(rows)

# Vulnerable reflected XSS endpoint
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # Vulnerable: returns raw HTML without escaping
    return f"<h1>Hello, {name}</h1>"

# Simple API used by Postman tests
@app.route('/api/items', methods=['GET','POST'])
def items():
    conn = get_db()
    cursor = conn.cursor()
    if request.method == 'POST':
        data = request.json or {}
        name = data.get('name','')
        cursor.execute("INSERT INTO items (name) VALUES (?)", (name,))
        return jsonify({'status':'created'}), 201
    cursor.execute("SELECT id,name FROM items")
    rows = cursor.fetchall()
    return jsonify([{'id':r[0],'name':r[1]} for r in rows])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
