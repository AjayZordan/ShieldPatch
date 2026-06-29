# backend/routes/auth_routes.py
print(">>> auth_routes imported")
from flask import Blueprint, request, jsonify, current_app
from sqlalchemy import text
import os
import datetime
import jwt
import bcrypt

# Use your models.py SQLAlchemy object (app already imports models elsewhere)
# We import models to access the db object and to get consistent session/engine behavior.
import models

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# JWT settings - read from environment if present
JWT_SECRET = os.getenv("JWT_SECRET", os.getenv("FLASK_SECRET", "supersecret_shieldpatch"))
JWT_ALGORITHM = "HS256"
JWT_EXP_DAYS = int(os.getenv("JWT_EXP_DAYS", "7"))

def _create_token(user_id):
    payload = {
        "user_id": int(user_id),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=JWT_EXP_DAYS),
        "iat": datetime.datetime.utcnow()
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    # PyJWT >= 2 returns str, older returns bytes
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token

def _token_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = None
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return jsonify({"message": "Authorization token required"}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("user_id")
            if not user_id:
                return jsonify({"message": "Token invalid (no user)"}), 401
            # fetch user from DB
            q = text("SELECT id, username, email, role, created_at FROM users WHERE id = :uid LIMIT 1")
            row = models.db.session.execute(q, {"uid": user_id}).first()
            if not row:
                return jsonify({"message": "User not found"}), 401
            # attach user to request context
            request.current_user = dict(row._mapping)
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401
        except Exception as e:
            current_app.logger.debug("token decode error: %s", e)
            return jsonify({"message": "Token invalid", "error": str(e)}), 401
        return func(*args, **kwargs)
    return wrapper

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    POST /api/auth/register
    body: { "username": "...", "email": "...", "password": "...", "role": "user" (optional) }
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"message": "Invalid JSON"}), 400

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    role = data.get("role") or "user"

    if not username or not email or not password:
        return jsonify({"message": "username, email and password are required"}), 400

    # check existing email or username
    try:
        q = text("SELECT id FROM users WHERE email = :email OR username = :username LIMIT 1")
        existing = models.db.session.execute(q, {"email": email, "username": username}).first()
        if existing:
            return jsonify({"message": "email or username already in use"}), 400

        # hash password with bcrypt
        salt = bcrypt.gensalt()
        pw_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

        insert_q = text("""
            INSERT INTO users (username, email, password_hash, role, created_at)
            VALUES (:username, :email, :pw, :role, :created_at)
        """)
        now = datetime.datetime.utcnow()
        res = models.db.session.execute(insert_q, {
            "username": username,
            "email": email,
            "pw": pw_hash,
            "role": role,
            "created_at": now
        })
        models.db.session.commit()

        # get new user id (last inserted id)
        # SQLAlchemy's .lastrowid may be accessible via result.provided in certain engines:
        user_id = res.lastrowid if hasattr(res, "lastrowid") else None
        if not user_id:
            # fallback: look up by email
            row = models.db.session.execute(text("SELECT id FROM users WHERE email = :email LIMIT 1"), {"email": email}).first()
            user_id = row._mapping["id"] if row else None

        token = _create_token(user_id)
        return jsonify({"message": "registered", "token": token, "user": {"id": user_id, "username": username, "email": email, "role": role}}), 201

    except Exception as e:
        models.db.session.rollback()
        current_app.logger.exception("register error: %s", e)
        return jsonify({"message": "registration failed", "error": str(e)}), 500

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    POST /api/auth/login
    body: { "email": "...", "password": "..." }
    returns: { token, user }
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"message": "Invalid JSON"}), 400

    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"message": "email and password are required"}), 400

    try:
        q = text("SELECT id, username, email, password_hash, role FROM users WHERE email = :email LIMIT 1")
        row = models.db.session.execute(q, {"email": email}).first()
        if not row:
            return jsonify({"message": "invalid credentials"}), 401

        user = row._mapping
        pw_hash = user.get("password_hash") or ""
        # verify bcrypt
        ok = False
        try:
            ok = bcrypt.checkpw(password.encode("utf-8"), pw_hash.encode("utf-8"))
        except Exception:
            ok = False

        if not ok:
            return jsonify({"message": "invalid credentials"}), 401

        # update last_login (if column exists)
        try:
            upd = text("UPDATE users SET last_login = :now WHERE id = :uid")
            models.db.session.execute(upd, {"now": datetime.datetime.utcnow(), "uid": user["id"]})
            models.db.session.commit()
        except Exception:
            models.db.session.rollback()

        token = _create_token(user["id"])
        user_payload = {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]}
        return jsonify({"message": "logged_in", "token": token, "user": user_payload}), 200

    except Exception as e:
        models.db.session.rollback()
        current_app.logger.exception("login error: %s", e)
        return jsonify({"message": "login failed", "error": str(e)}), 500

@auth_bp.route("/me", methods=["GET"])
@_token_required
def me():
    """
    GET /api/auth/me
    Headers: Authorization: Bearer <token>
    """
    u = request.current_user
    # return safe fields
    return jsonify({
        "id": u.get("id"),
        "username": u.get("username"),
        "email": u.get("email"),
        "role": u.get("role"),
        "created_at": u.get("created_at").isoformat() if u.get("created_at") else None
    }), 200
