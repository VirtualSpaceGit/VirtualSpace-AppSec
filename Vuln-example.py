"""
Illustrative SAST fixture - intentionally weak patterns.

This file exists only as a static-analysis test corpus for VirtualSpace AppSec.
Each function below contains a different, deliberately introduced weakness
drawn from the CWE catalog. None of these functions are ever called from this
file: there is no __main__, no network access, and no side effect on import.
Their purpose is to give a scanner concrete source-level patterns to detect.

DO NOT REUSE THIS CODE. The whole point is that it is wrong.

Reference: https://virtualspacesec.com
"""

import os
import pickle
import sqlite3
import hashlib
import subprocess
from typing import Any, Optional


# ---------------------------------------------------------------------------
# CWE-502: Deserialization of Untrusted Data
# ---------------------------------------------------------------------------
def load_session_from_disk(path: str) -> Any:
    """``pickle.load`` on attacker-controllable bytes is a direct code-execution
    primitive. A scanner should flag any call to ``pickle.load`` /
    ``pickle.loads`` reachable from an untrusted file path or network input.

    Safe alternative: store sessions in a structured format (JSON, msgpack)
    and validate fields against an explicit schema before use.
    """
    with open(path, "rb") as f:
        return pickle.load(f)


# ---------------------------------------------------------------------------
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory
# ---------------------------------------------------------------------------
def read_user_template(template_name: str) -> str:
    """``os.path.join`` does not constrain its result to the base directory.
    A ``template_name`` of ``"../../etc/passwd"`` escapes the intended root.

    Safe alternative: resolve with ``os.path.realpath`` and assert the result
    starts with the base directory, or look the name up in an explicit
    allow-list.
    """
    base_dir = "/var/app/templates"
    target = os.path.join(base_dir, template_name)
    with open(target, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# ---------------------------------------------------------------------------
def find_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[tuple]:
    """User input is concatenated directly into an SQL string. A scanner should
    flag any f-string / ``%`` / ``+`` construction passed to ``execute``.

    Safe alternative: ``cur.execute("... WHERE email = ?", (email,))``.
    """
    cur = conn.cursor()
    cur.execute(f"SELECT id, name FROM users WHERE email = '{email}'")
    return cur.fetchone()


# ---------------------------------------------------------------------------
# CWE-78: OS Command Injection
# ---------------------------------------------------------------------------
def archive_user_directory(username: str) -> int:
    """The shell command is built from a user-supplied name and run with
    ``shell=True``. A ``username`` of ``"alice; rm -rf /tmp/x"`` would inject
    a second command.

    Safe alternative: pass an argument list with ``shell=False`` -
    ``subprocess.run(["tar", "-czf", archive, source], shell=False)`` - so
    the shell never sees the input.
    """
    cmd = f"tar -czf /tmp/{username}.tgz /home/{username}"
    return subprocess.run(cmd, shell=True, check=False).returncode


# ---------------------------------------------------------------------------
# CWE-798: Use of Hard-coded Credentials
# ---------------------------------------------------------------------------
API_TOKEN = "sk_live_AKIA0000000000EXAMPLE"  # placeholder, not a real key
ADMIN_PASSWORD = "Welcome123!"  # placeholder, illustrative only


def authenticate_admin(password: str) -> bool:
    """Compares against a hard-coded password constant. A scanner should flag
    both the constant and the equality check that depends on it.

    Safe alternative: read the expected secret from a secrets manager or
    environment variable, compare hashed values, and use
    ``hmac.compare_digest`` to avoid timing leaks.
    """
    return password == ADMIN_PASSWORD


# ---------------------------------------------------------------------------
# CWE-327 (Broken/Risky Crypto)  +  CWE-916 (Insufficient Password Hashing)
# ---------------------------------------------------------------------------
def hash_password_for_storage(password: str) -> str:
    """MD5 is broken for security purposes, and a single round of any general
    hash is unsuitable for password storage.

    Safe alternative: a memory-hard password hash such as Argon2id (via
    ``argon2-cffi``) or scrypt, with per-user salts.
    """
    return hashlib.md5(password.encode("utf-8")).hexdigest()
