try:
    from androguard.core.apk import APK
except Exception:
    from androguard.core.bytecodes.apk import APK


apk_path = "/Users/ajaykumar/Desktop/ShieldPatch/files/microsoft-word.apk"

try:
    a = APK(apk_path)
    print("✅ APK successfully loaded!")
    print("📦 Package Name:", a.get_package())
    print("📄 App Name:", a.get_app_name())
    print("🔐 Permissions:")
    for perm in a.get_permissions():
        print("  -", perm)
    print("\n🧩 Activities:")
    for act in a.get_activities():
        print("  -", act)
except Exception as e:
    print("❌ Error analyzing APK:", e)