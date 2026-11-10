"""Secrets come from the environment (or a secret manager), never from code.

The planted values from `main` were fake. If they had been real, deleting them
here would not be enough: they stay in git history and must be rotated.
"""

import os

DATABASE_URL = os.environ["DATABASE_URL"]
PAYMENT_API_KEY = os.environ["PAYMENT_API_KEY"]
JWT_SIGNING_SECRET = os.environ["JWT_SIGNING_SECRET"]
