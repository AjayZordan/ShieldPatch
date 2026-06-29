# backend/utils/scanner.py
import os
import hashlib
import json
import tempfile
from typing import Dict, Any

try:
    import pefile
except Exception:
    pefile = None

try:
    try:
    from androguard.core.apk import APK
except Exception:
    from androguard.core.bytecodes.apk import APK

except Exception:
    APK = None

try:
    import yara
except Exception:
    yara = None

# Optional clamd usage
try:
    import clamd
except Exception:
    clamd = None

# Example minimal yara rules (you can expand)
SIMPLE_YARA_SOURCE = r'''
rule SuspiciousString {
    strings:
        $s1 = "eval(" wide ascii
        $s2 = "base64_decode(" wide ascii
    condition:
        any of them
}
'''

yara_ruleset = None
if yara:
    try:
        yara_ruleset = yara.compile(source=SIMPLE_YARA_SOURCE)
    except Exception:
        yara_ruleset = None


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def run_yara(path: str):
    if not yara_ruleset:
        return None
    try:
        matches = yara_ruleset.match(path)
        return [m.rule for m in matches]
    except Exception:
        return None


def clamav_scan(path: str):
    if not clamd:
        return None
    try:
        cd = clamd.ClamdUnixSocket()  # or ClamdNetworkSocket(host, port)
        resp = cd.scan(path)
        return resp
    except Exception:
        return None


def scan_file_on_disk(path: str) -> Dict[str, Any]:
    """
    Minimal scan: compute hash, detect type (exe/apk/other), run pefile/androguard basics,
    optional yara and clamav.
    """
    out = {
        "sha256": sha256_of_file(path),
        "filename": os.path.basename(path),
        "size_bytes": os.path.getsize(path),
        "detected_type": None,
        "metadata": {},
        "yara_matches": None,
        "clamav": None,
    }

    # YARA
    try:
        out["yara_matches"] = run_yara(path)
    except Exception:
        out["yara_matches"] = None

    # ClamAV
    try:
        out["clamav"] = clamav_scan(path)
    except Exception:
        out["clamav"] = None

    # PE (Windows exe/dll)
    if pefile:
        try:
            pe = pefile.PE(path, fast_load=True)
            out["detected_type"] = "pe"
            md = {}
            md["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(pe, "OPTIONAL_HEADER") else None
            md["timestamp"] = getattr(pe.FILE_HEADER, "TimeDateStamp", None)
            md["dll_char"] = getattr(pe.FILE_HEADER, "Characteristics", None)
            out["metadata"]["pe"] = md
        except Exception:
            pass

    # APK
    if APK and out["detected_type"] is None:
        try:
            a = APK(path)
            if a.is_valid_APK():
                out["detected_type"] = "apk"
                out["metadata"]["apk"] = {
                    "package": a.get_package(),
                    "version_name": a.get_androidversion_name(),
                    "permissions": a.get_permissions(),
                    "activities": a.get_activities()
                }
        except Exception:
            pass

    # fallback file type
    if not out["detected_type"]:
        # basic extension sniff
        _, ext = os.path.splitext(out["filename"])
        ext = ext.lower().strip(".")
        if ext in ("exe", "dll"):
            out["detected_type"] = "exe"
        elif ext in ("apk",):
            out["detected_type"] = "apk"
        else:
            out["detected_type"] = ext or "unknown"

    return out


def scan_file(file_storage) -> Dict[str, Any]:
    """
    file_storage is a werkzeug FileStorage object from Flask request.files['file'].
    We save to a temp file, run scan_file_on_disk, then remove the temp file.
    """
    fd, tmp = None, None
    try:
        fd, tmp = tempfile.mkstemp(prefix="upload_scan_", suffix=os.path.splitext(file_storage.filename)[1] or "")
        with os.fdopen(fd, "wb") as f:
            file_storage.stream.seek(0)
            f.write(file_storage.read())
        return scan_file_on_disk(tmp)
    finally:
        try:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass