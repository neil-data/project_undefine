# E-Rakshak Forensic Threat Triage -- Infrastructure & Benign Host Allowlist
# Date: 2026-10-04 (Day 2 Audit Standard)
# Description: Authoritative allowlist of legitimate system infrastructure,
# public recursive DNS resolvers, and benign vendor/OS hosts. Indicators matching
# these entries are classified as SYSTEM_INFRASTRUCTURE (informational only)
# and must NEVER be flagged as C2, suspicious, or malicious.

# 2026-10-04: Public DNS Resolvers (standard Anycast resolvers)
PUBLIC_DNS_RESOLVERS = {
    "8.8.8.8",         # Google Public DNS primary
    "8.8.4.4",         # Google Public DNS secondary
    "1.1.1.1",         # Cloudflare Public DNS primary
    "1.0.0.1",         # Cloudflare Public DNS secondary
    "9.9.9.9",         # Quad9 Public DNS primary
    "149.112.112.112", # Quad9 Public DNS secondary
    "208.67.222.222",  # Cisco OpenDNS Home primary
    "208.67.220.220",  # Cisco OpenDNS Home secondary
}

# 2026-10-04: Legitimate platform vendor and developer infrastructure hosts
LEGITIMATE_BENIGN_DOMAINS = {
    "go.dev",
    "golang.org",
    "microsoft.com",
    "developer.microsoft.com",
    "android.googlesource.com",
    "google.com",
    "github.com",
    "ocsp.apple.com",
    "crl.apple.com",
    "certs.apple.com",
    "valid.apple.com",
    "ocsp2.apple.com",
}

# 2026-10-04: Systemd unit suffixes (not legitimate TLRs)
SYSTEMD_SUFFIXES = {
    "local",
    "target",
    "service",
    "socket",
    "mount",
    "automount",
    "timer",
    "path",
    "scope",
    "slice",
    "swap",
    "device",
}

# 2026-10-04: File extensions commonly misidentified as domain TLDs
COMMON_FILE_EXTENSIONS = {
    "html", "htm", "php", "js", "css", "txt", "conf", "cfg",
    "sh", "py", "so", "a", "o", "bin", "dat", "log", "xml",
    "json", "png", "jpg", "jpeg", "gif", "ico", "dex", "exe",
    "dll", "elf", "tar", "gz", "zip",
}

# 2026-10-04: Go standard library / runtime package prefixes
GO_PACKAGE_PREFIXES = {
    "fmt", "go", "io", "os", "runtime", "sync", "bytes", "strings",
    "net", "math", "time", "bufio", "path", "sort", "strconv",
    "context", "errors", "syscall", "reflect", "unicode",
}

# 2026-10-04: System libraries frequently flagged falsely as install paths
SYSTEM_LIBRARIES = {
    "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
    "gdi32.dll", "ws2_32.dll", "shell32.dll", "ole32.dll",
    "/lib/libc.so", "/lib/libc.so.6", "/lib64/ld-linux-x86-64.so.2",
    "/lib64/ld-linux", "libc.so", "libdl.so", "libm.so", "libpthread.so",
}
