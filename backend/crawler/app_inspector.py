import zipfile
from pathlib import Path


def inspect_apk(path: str | Path) -> dict:
    """Extract safe static metadata from an APK without executing it."""
    apk_path = Path(path)
    if apk_path.suffix.lower() != ".apk":
        raise ValueError("Only .apk files are supported")
    if not apk_path.is_file():
        raise FileNotFoundError(apk_path)
    with zipfile.ZipFile(apk_path) as archive:
        names = archive.namelist()
        suspicious_permissions = [
            permission for permission in (
                "SEND_SMS", "READ_SMS", "REQUEST_INSTALL_PACKAGES",
                "SYSTEM_ALERT_WINDOW", "QUERY_ALL_PACKAGES",
            )
            if any(permission in name for name in names)
        ]
        return {
            "filename": apk_path.name,
            "size_bytes": apk_path.stat().st_size,
            "has_manifest": "AndroidManifest.xml" in names,
            "dex_files": len([name for name in names if name.endswith(".dex")]),
            "native_libraries": len([name for name in names if name.startswith("lib/")]),
            "suspicious_permission_markers": suspicious_permissions,
        }
