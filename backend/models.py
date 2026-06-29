# models.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.mysql import LONGTEXT

db = SQLAlchemy()

# 1️⃣ Agent table – stores agent IP, status, and last heartbeat
class Agent(db.Model):
    __tablename__ = "agents"
    id = db.Column(db.Integer, primary_key=True)
    agent_ip = db.Column(db.String(64), nullable=False, index=True)
    user_agent = db.Column(db.String(256))
    status = db.Column(db.String(32), default="offline")
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    extra = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "agent_ip": self.agent_ip,
            "user_agent": self.user_agent,
            "status": self.status,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "extra": self.extra,
        }

# 2️⃣ Scan results – every file or vulnerability scan is stored here
class ScanResult(db.Model):
    __tablename__ = "scan_results"
    id = db.Column(db.Integer, primary_key=True)

    # foreign key to users.id — keep as INT and FK, no relationship object to avoid import-order issues
    user_id = db.Column(db.Integer, nullable=True)

    # fields matching your MySQL schema
    scan_type = db.Column(db.String(20))        # varchar(20)
    result = db.Column(db.JSON)                 # json
    scan_date = db.Column(db.DateTime)          # timestamp
    filename = db.Column(db.String(255))        # varchar(255)
    summary = db.Column(db.Text)                # text
    raw_result = db.Column(db.JSON)             # json
    source = db.Column(db.String(128))          # varchar(128)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # extended fields you added via ALTER TABLE
    software = db.Column(db.String(255))
    cve = db.Column(db.String(255))
    description = db.Column(db.Text)
    severity = db.Column(db.String(32))
    risk_score = db.Column(db.Integer, default=0)
    color = db.Column(db.String(32))

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "scan_type": self.scan_type,
            "result": self.result,
            "scan_date": self.scan_date.isoformat() if self.scan_date else None,
            "filename": self.filename,
            "summary": self.summary,
            "raw_result": self.raw_result,
            "source": self.source,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "software": self.software,
            "cve": self.cve,
            "description": self.description,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "color": self.color,
        }

# 3️⃣ Package table – discovered installed apps or system packages
class Package(db.Model):
    __tablename__ = "packages"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(512), nullable=False)
    version = db.Column(db.String(128))
    path = db.Column(db.String(1024))
    discovered_by = db.Column(db.String(64))  # osquery/manual
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "path": self.path,
            "discovered_by": self.discovered_by,
            "discovered_at": self.discovered_at.isoformat(),
        }

# 4️⃣ CVE table – vulnerability data (for later threat-intelligence use)
class CVE(db.Model):
    __tablename__ = "cves"
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(64), unique=True, index=True)
    summary = db.Column(db.Text)
    published = db.Column(db.DateTime)
    last_modified = db.Column(db.DateTime)
    severity = db.Column(db.String(64))

    # NEW FIELDS (safe additions to support ingestion & scoring)
    cvss_v3 = db.Column(db.Float, nullable=True)          # numeric CVSS v3 score
    vector = db.Column(db.String(128), nullable=True)     # CVSS vector string
    references = db.Column(LONGTEXT, nullable=True)       # JSON/text blob with links
    source = db.Column(db.String(120), nullable=True)     # which feed provided this record (e.g. 'NVD')
    last_updated = db.Column(db.DateTime, nullable=True)  # when ingestion last updated this record

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "summary": self.summary,
            "published": self.published.isoformat() if self.published else None,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "severity": self.severity,
            "cvss_v3": self.cvss_v3,
            "vector": self.vector,
            "references": self.references,
            "source": self.source,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

# 5️⃣ Threat feed metadata (which feeds we poll)
class ThreatFeed(db.Model):
    __tablename__ = "threat_feeds"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    url = db.Column(db.String(1024), nullable=False)
    type = db.Column(db.String(32), nullable=False)  # e.g., "rss","json","nvd","otx"
    last_checked = db.Column(db.DateTime, nullable=True)
    etag = db.Column(db.String(256), nullable=True)
    last_modified = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "type": self.type,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
            "etag": self.etag,
            "last_modified": self.last_modified,
            "created_at": self.created_at.isoformat(),
        }

# 6️⃣ Threat indicators (canonical table used going forward)
class ThreatIndicator(db.Model):
    __tablename__ = "threat_indicators"
    id = db.Column(db.Integer, primary_key=True)
    feed_id = db.Column(db.Integer, db.ForeignKey("threat_feeds.id"), nullable=True)
    type = db.Column(db.String(32), nullable=False)  # ip, url, domain, cve, hash
    value = db.Column(db.String(512), nullable=False, index=True)
    description = db.Column(LONGTEXT, nullable=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    raw = db.Column(LONGTEXT, nullable=True)  # store raw JSON or text blob
    score = db.Column(db.Integer, nullable=True)  # optional severity/score
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    feed = db.relationship("ThreatFeed", backref=db.backref("indicators", lazy="dynamic"))

    def to_dict(self):
        return {
            "id": self.id,
            "feed_id": self.feed_id,
            "type": self.type,
            "value": self.value,
            "description": self.description,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "score": self.score,
            "created_at": self.created_at.isoformat(),
        }

# 7️⃣ Backward-compatible simple Threat table (for legacy endpoints that used /api/threats -> 'threats')
class Threat(db.Model):
    __tablename__ = "threats"
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(255))
    ioc = db.Column(db.Text)                # IOC string (url, ip, domain, hash, etc.)
    type = db.Column(db.String(100))        # 
    description = db.Column(db.Text)
    first_seen = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "source": self.source,
            "ioc": self.ioc,
            "type": self.type,
            "description": self.description,
            "first_seen": self.first_seen,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

# 8️⃣ Vulnerability table — used by vuln_api import / lookup
class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"
    id = db.Column(db.Integer, primary_key=True)
    # keep foreign key to cves.cve_id for integrity; allows NULL if cve not present
    cve_id = db.Column(db.String(64), db.ForeignKey("cves.cve_id", ondelete="SET NULL", onupdate="CASCADE"), nullable=True, index=True)
    description = db.Column(db.Text)
    published = db.Column(db.DateTime, nullable=True)
    last_modified = db.Column(db.DateTime, nullable=True)
    severity = db.Column(db.String(64), nullable=True)
    raw_data = db.Column(LONGTEXT, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    affected_os = db.Column(db.String(255))
    

    def as_dict(self):
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "description": self.description,
            "published": self.published.isoformat() if self.published else None,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "severity": self.severity,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

# 9️⃣ RiskLog table — logs inputs and outputs of risk scoring models    
class RiskLog(db.Model):
    __tablename__ = "risk_logs"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    cve_id = db.Column(db.String(100), nullable=True)
   
    predicted_score = db.Column(db.Float, nullable=False)
    severity = db.Column(db.String(20), nullable=False)   # ✅ ADD THIS
    input_payload = db.Column(db.JSON, nullable=False)
    model_name = db.Column(db.String(100), nullable=True)
    extra_info = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "input_payload": self.input_payload,
            "predicted_score": self.predicted_score,
            "model_name": self.model_name,
            "extra_info": self.extra_info,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

# 🔁 Snapshot table — persisting container image snapshots created by sandbox operations
class Snapshot(db.Model):
    __tablename__ = "snapshots"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    image_tag = db.Column(db.String(255), nullable=False, unique=True)
    image_id = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by = db.Column(db.String(128), nullable=True)   # container name or user id
    host_data_dir = db.Column(db.Text, nullable=True)
    meta = db.Column(db.JSON, nullable=True)                # store commit stdout/stderr and other metadata

    def to_dict(self):
        return {
            "id": int(self.id),
            "image_tag": self.image_tag,
            "image_id": self.image_id,
            "created_at": (self.created_at.isoformat() if self.created_at else None),
            "created_by": self.created_by,
            "host_data_dir": self.host_data_dir,
            "meta": self.meta
        }
    
# add to models.py (paste near the other models)
class JobImage(db.Model):
    __tablename__ = "job_images"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    image_tag = db.Column(db.String(255), nullable=False)
    image_id = db.Column(db.String(255), nullable=False)
    container_name = db.Column(db.String(255), nullable=True)
    job_name = db.Column(db.String(255), nullable=True)
    succeeded = db.Column(db.Boolean, default=False)
    stdout = db.Column(db.Text, nullable=True)
    stderr = db.Column(db.Text, nullable=True)
    snapshot_tag = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, nullable=True)
    host_path = db.Column(db.String(1024), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "image_tag": self.image_tag,
            "image_id": self.image_id,
            "container_name": self.container_name,
            "job_name": self.job_name,
            "succeeded": bool(self.succeeded),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "snapshot_tag": self.snapshot_tag,
            "user_id": self.user_id,
            "host_path": self.host_path,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }    