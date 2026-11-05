"""
api-backend — Mini-projet 6 : cycle de vie des secrets.

Ce service existe pour démontrer trois propriétés du projet :

1. Le secret n'est JAMAIS lu depuis une variable d'environnement : il est monté
   en volume et lu à la demande depuis le système de fichiers.
2. La rotation est prise en compte SANS redémarrage : aucun cache, chaque
   requête relit le fichier. Le kubelet met à jour le contenu du volume monté
   quand le Secret change (~60 s), et le fichier suit.
3. Les endpoints révèlent uniquement des EMPREINTES (SHA-256 tronqué), jamais
   la valeur du secret : on peut prouver une rotation sans jamais l'afficher.

Aucune dépendance obligatoire : si psycopg est absent, /api/db-check dégrade
proprement en test de connexion TCP.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRETS_DIR = os.environ.get("SECRETS_DIR", "/etc/app-secrets")
DB_SECRET_DIR = os.path.join(SECRETS_DIR, "db-credentials")
JWT_SECRET_DIR = os.path.join(SECRETS_DIR, "jwt-key")
PORT = int(os.environ.get("APP_PORT", "8080"))


def read_secret(directory: str, key: str) -> str:
    """Lit un fichier de secret. Aucun cache : voir docstring du module."""
    with open(os.path.join(directory, key), "r", encoding="utf-8") as handle:
        return handle.read().strip()


def fingerprint(value: str) -> str:
    """Empreinte non réversible : preuve de rotation sans fuite de valeur."""
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def file_metadata(path: str) -> dict:
    stat = os.stat(path)
    return {
        "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
        "age_seconds": int(time.time() - stat.st_mtime),
        "size": stat.st_size,
    }


def db_check() -> dict:
    """Connexion PostgreSQL avec le mot de passe lu sur le volume monté."""
    params = {
        "host": read_secret(DB_SECRET_DIR, "host"),
        "port": int(read_secret(DB_SECRET_DIR, "port")),
        "user": read_secret(DB_SECRET_DIR, "username"),
        "password": read_secret(DB_SECRET_DIR, "password"),
        "dbname": read_secret(DB_SECRET_DIR, "database"),
    }
    started = time.time()
    try:
        import psycopg  # import tardif : l'image de base reste utilisable sans
    except ImportError:
        with socket.create_connection((params["host"], params["port"]), timeout=3):
            return {
                "driver": "tcp-only",
                "ok": True,
                "latency_ms": round((time.time() - started) * 1000, 1),
                "note": "psycopg absent : simple test de joignabilité TCP",
            }

    with psycopg.connect(
        host=params["host"],
        port=params["port"],
        user=params["user"],
        password=params["password"],
        dbname=params["dbname"],
        connect_timeout=3,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_user, current_database(), now()::text")
            user, database, server_time = cur.fetchone()
            cur.execute("SELECT count(*) FROM demo_events")
            (events,) = cur.fetchone()
    return {
        "driver": "psycopg",
        "ok": True,
        "latency_ms": round((time.time() - started) * 1000, 1),
        "connected_as": user,
        "database": database,
        "server_time": server_time,
        "demo_events": events,
        "password_fingerprint": fingerprint(params["password"]),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "api-backend/1.0"

    def log_message(self, fmt: str, *args) -> None:  # pas de secret dans les logs
        print("[api-backend] %s - %s" % (self.address_string(), fmt % args), flush=True)

    def _send(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (API http.server)
        path = self.path.split("?")[0].rstrip("/") or "/"
        try:
            if path == "/healthz":
                self._send({"status": "ok"})

            elif path == "/":
                self._send(
                    {
                        "service": "api-backend",
                        "endpoints": [
                            "/healthz",
                            "/api/whoami",
                            "/api/db-check",
                            "/api/secret-fingerprint",
                        ],
                    }
                )

            elif path == "/api/whoami":
                self._send(
                    {
                        "pod": socket.gethostname(),
                        "service_account": open(
                            "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
                            encoding="utf-8",
                        ).read().strip()
                        if os.path.exists(
                            "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
                        )
                        else "inconnu",
                        "mounted_secrets": sorted(os.listdir(SECRETS_DIR))
                        if os.path.isdir(SECRETS_DIR)
                        else [],
                        "note": "secrets montés en volume, aucune variable d'env",
                    }
                )

            elif path == "/api/secret-fingerprint":
                password = read_secret(DB_SECRET_DIR, "password")
                signing_key = read_secret(JWT_SECRET_DIR, "signing-key")
                self._send(
                    {
                        "db_password": {
                            "sha256_prefix": fingerprint(password),
                            "length": len(password),
                            **file_metadata(os.path.join(DB_SECRET_DIR, "password")),
                        },
                        "jwt_signing_key": {
                            "sha256_prefix": fingerprint(signing_key),
                            "length": len(signing_key),
                        },
                        "explanation": (
                            "Empreintes seules. Deux appels successifs avec un "
                            "sha256_prefix différent prouvent une rotation prise "
                            "en compte sans redémarrage."
                        ),
                    }
                )

            elif path == "/api/db-check":
                self._send(db_check())

            else:
                self._send({"error": "not found", "path": path}, 404)

        except Exception as exc:  # noqa: BLE001 — on renvoie l'erreur telle quelle
            self._send(
                {"error": type(exc).__name__, "detail": str(exc), "path": path}, 500
            )


if __name__ == "__main__":
    print(f"[api-backend] écoute sur 0.0.0.0:{PORT}, secrets dans {SECRETS_DIR}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
