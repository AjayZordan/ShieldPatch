# server.py
from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import os

from models import db                     # ✅ Flask-SQLAlchemy
from routes.vulnlookup_routes import vuln_bp  # ✅ correct blueprint

# --------------------------------------------------
# App setup
# --------------------------------------------------
load_dotenv()

app = Flask(__name__)
CORS(app)

# --------------------------------------------------
# Config
# --------------------------------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "mysql+pymysql://root:password@localhost/shieldpatch"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --------------------------------------------------
# Init DB
# --------------------------------------------------
db.init_app(app)

with app.app_context():
    db.create_all()   # ✅ replaces Base.metadata.create_all

# --------------------------------------------------
# Blueprints
# --------------------------------------------------
app.register_blueprint(vuln_bp)

# --------------------------------------------------
# Health check
# --------------------------------------------------
@app.route("/api/health")
def health():
    return jsonify({
        "ok": True,
        "service": "shieldpatch"
    })

# --------------------------------------------------
# Run
# --------------------------------------------------
if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", 5000))
    app.run(host=host, port=port, debug=True)