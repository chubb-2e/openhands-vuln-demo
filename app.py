"""
Mini Notes App
--------------
아주 작은 메모 공유용 Flask 웹앱입니다.
사용자가 로그인해서 메모를 남기고, 서버 상태를 점검(ping)할 수 있습니다.

(주의) 이 파일은 OpenHands 데모용으로 만든 예제이며,
아래에 "일부러" 흔한 보안 취약점 3가지를 심어 놓았습니다:
  1) 하드코딩된 시크릿 값 (SECRET_KEY / ADMIN_PASSWORD)
  2) SQL Injection (사용자 입력을 그대로 쿼리 문자열에 이어붙임)
  3) OS Command Injection (사용자 입력을 그대로 셸 명령에 이어붙임)

실제 서비스 코드로 절대 쓰지 마세요.
"""

import os
import sqlite3

from flask import Flask, request, g

app = Flask(__name__)

# --- 취약점 1: 하드코딩된 시크릿 -------------------------------------------
# 세션 서명 키와 관리자 비밀번호를 소스코드에 직접 박아놓음.
SECRET_KEY = "sk-live-9f8a2c7b1e4d4f0aa2c6e5b7d0f13a9c"
ADMIN_PASSWORD = "admin1234!"

app.config["SECRET_KEY"] = SECRET_KEY

DB_PATH = os.path.join(os.path.dirname(__file__), "notes.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS notes (username TEXT, body TEXT)"
    )
    conn.execute(
        "INSERT INTO users (username, password) VALUES ('grlee', 'password123')"
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    """사용자 로그인.

    취약점 2: SQL Injection
    username/password를 그대로 쿼리 문자열에 이어붙여서,
    username 에 " OR '1'='1' -- " 같은 값을 넣으면 인증이 우회됩니다.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    db = get_db()
    cursor = db.execute(query)
    user = cursor.fetchone()

    if user:
        return {"status": "ok", "message": f"welcome {username}"}
    return {"status": "error", "message": "invalid credentials"}, 401


@app.route("/ping", methods=["GET"])
def ping():
    """서버가 특정 호스트로 연결 가능한지 점검하는 진단용 엔드포인트.

    취약점 3: OS Command Injection
    host 파라미터를 검증 없이 셸 명령에 그대로 이어붙여서,
    host 에 "example.com; rm -rf /" 같은 값을 넣으면 임의 명령이 실행됩니다.
    """
    host = request.args.get("host", "localhost")
    result = os.system("ping -c 1 " + host)
    return {"status": "done", "exit_code": result}


@app.route("/notes", methods=["POST"])
def add_note():
    """메모 추가 (이 엔드포인트는 파라미터화된 쿼리를 이미 쓰고 있어서 안전합니다)."""
    username = request.form.get("username", "")
    body = request.form.get("body", "")

    db = get_db()
    db.execute(
        "INSERT INTO notes (username, body) VALUES (?, ?)",
        (username, body),
    )
    db.commit()
    return {"status": "ok"}


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
