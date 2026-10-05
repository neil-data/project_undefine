def select_provider(platform, architecture):
    platform = str(platform).upper().replace("-", "")
    architecture = str(architecture).lower()
    if platform == "ELF":
        return "hybrid_analysis" if architecture in {"x86_64", "amd64", "x64"} else None
    if platform in {"EXE", "PE", "DLL"}:
        return "hybrid_analysis"
    if platform == "APK":
        return "mobsf"
    return None
