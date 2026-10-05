# MobSF live-check checklist

Perform only after pinning and verifying the installed MobSF version's own
API routes and docs. Use an isolated VM and emulator only; never a physical
device. Do not sign in to accounts. Start from a clean emulator snapshot.

1. Upload a benign APK and verify static scan, report retrieval, and deletion.
2. Revert the clean snapshot. Run the benign APK dynamically with an explicit
   timeout; verify start, install, main-activity launch, stop, report retrieval,
   and uploaded-scan deletion.
3. Confirm the report warns that sample network traffic may leave the emulator.
4. Revert the clean snapshot and verify isolation again before considering a
   public malware APK. Keep the host VM isolated throughout.
5. Revert the clean snapshot after each run and retain only sanitized report
   metadata; do not persist sample bytes in E-Rakshak artifacts.
