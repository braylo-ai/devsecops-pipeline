"""Fixed version of the payments service (``fixed`` branch).

Each block names the planted finding it replaces.
"""

import hashlib
import hmac
import json
import os
import re
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, abort, request

app = Flask(__name__)
FINGERPRINT_KEY = os.environ.get("FINGERPRINT_KEY", "").encode()
SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@app.get("/invoice")
def invoice():
    con = sqlite3.connect("payments.db")
    # FIX-1: parameterised query.
    cur = con.execute("SELECT * FROM invoices WHERE id = ?", (request.args["id"],))
    return {"rows": cur.fetchall()}


@app.post("/export")
def export():
    # FIX-2: allow-listed name, argument list, no shell.
    name = request.form["name"]
    if not SAFE_NAME.match(name):
        abort(400)
    subprocess.run(["tar", "czf", f"/tmp/{name}.tgz", "/srv/exports"], check=True)
    return {"ok": True}


@app.post("/import")
def import_profile():
    # FIX-3: JSON instead of pickle.
    return {"profile": json.loads(request.data)}


@app.post("/config")
def load_config():
    # FIX-4: safe_load builds plain data types only.
    return {"cfg": yaml.safe_load(request.data)}


def fingerprint(card_number: str) -> str:
    # FIX-5: keyed HMAC-SHA256, key from the environment.
    return hmac.new(FINGERPRINT_KEY, card_number.encode(), hashlib.sha256).hexdigest()


def call_bank(url: str):
    # FIX-6: TLS verification on (the default).
    return requests.get(url, timeout=5)


@app.get("/calc")
def calc():
    # FIX-7: no eval; accept two integers and one operator.
    a, op, b = int(request.args["a"]), request.args["op"], int(request.args["b"])
    ops = {"+": a + b, "-": a - b, "*": a * b}
    if op not in ops:
        abort(400)
    return {"result": ops[op]}


if __name__ == "__main__":
    # FIX-8: no debug, loopback only.
    app.run(host="127.0.0.1", debug=False)
