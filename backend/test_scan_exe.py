import pefile

exe_path = "/Users/ajaykumar/Desktop/ShieldPatch/files/notepad.exe"

try:
    pe = pefile.PE(exe_path)
    print("EXE successfully loaded!")
    print("Sections:")
    for section in pe.sections:
        print(f"  {section.Name.decode().strip()}  Size: {section.SizeOfRawData}")
    print("\nImported DLLs:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"  - {entry.dll.decode()}")
except Exception as e:
    print("Error analyzing EXE:", e)
    