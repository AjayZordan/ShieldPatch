# utils/androguard_import.py
"""
Single place to import APK from androguard with backwards-compat fallback.
Import like:
    from utils.androguard_import import APK
"""
try:
    # preferred modern path
    from androguard.core.apk import APK  # type: ignore
except Exception:
    # fallback for older androguard versions
    from androguard.core.bytecodes.apk import APK  # type: ignore