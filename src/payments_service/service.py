"""PLANTED FINDINGS (main branch). Each block below is an intentional bug for the
SAST stage to catch. The `fixed` branch replaces this file with safe code.
Never deploy this file.
"""

import hashlib
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.get("/invoice")
def invoice():
    con = sqlite3.connect("payments.db")
    # PLANTED-SAST-1: SQL injection via string formatting.
    cur = con.execute("SELECT * FROM invoices WHERE id = '%s'" % request.args["id"])
    return {"rows": cur.fetchall()}


@app.post("/export")
def export():
    # PLANTED-SAST-2: OS command injection (shell=True with user input).
    name = request.form["name"]
    subprocess.call("tar czf /tmp/" + name + ".tgz /srv/exports", shell=True)
    return {"ok": True}


@app.post("/import")
def import_profile():
    # PLANTED-SAST-3: insecure deserialisation.
    return {"profile": str(pickle.loads(request.data))}


@app.post("/config")
def load_config():
    # PLANTED-SAST-4: unsafe YAML load (arbitrary object construction).
    return {"cfg": str(yaml.load(request.data, Loader=yaml.Loader))}


def fingerprint(card_number: str) -> str:
    # PLANTED-SAST-5: MD5 for a security-relevant hash.
    return hashlib.md5(card_number.encode()).hexdigest()


def call_bank(url: str):
    # PLANTED-SAST-6: TLS verification disabled.
    return requests.get(url, verify=False, timeout=5)


@app.get("/calc")
def calc():
    # PLANTED-SAST-7: eval on user input.
    return {"result": eval(request.args["expr"])}


if __name__ == "__main__":
    # PLANTED-SAST-8: debug server bound to all interfaces.
    app.run(host="0.0.0.0", debug=True)
