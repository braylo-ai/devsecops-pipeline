"""PLANTED FINDINGS (main branch): hard-coded secrets.

Every value below is FAKE. Each contains the marker PLANTED_FAKE so nobody can
mistake it for a real credential, and none uses a real provider's token format
(GitHub push protection and real scanners would block those). The custom rules
in .gitleaks.toml detect the marker.
"""

DATABASE_URL = "postgres://payments:PLANTED_FAKE_db_password_0001@db.internal:5432/payments"
STRIPE_KEY = "PLANTED_FAKE_payment_api_key_0002_not_real"
JWT_SIGNING_SECRET = "PLANTED_FAKE_jwt_signing_secret_0003"
