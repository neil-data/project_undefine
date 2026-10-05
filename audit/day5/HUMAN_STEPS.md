# Human-Run Steps for Day 5 Provider Recordings

Follow these exact PowerShell steps in order on the host environment:

### Step (a): Pin MobSF Docker tag in docker-compose
Check running containers and image digest:
```powershell
docker ps --format "{{.Names}}  {{.Image}}  {{.Status}}"
docker images --digest
```
Note the MobSF tag/digest, find the exact version in the MobSF UI, pin that version tag in `docker-compose.yml` replacing `latest`, and restart:
```powershell
docker-compose down mobsf
docker-compose up -d mobsf
```

### Step (b): Confirm both .env files exist and are git-ignored
```powershell
git check-ignore -v .env sandbox/adapters/mobsf/.env
```
Ensure both files are confirmed ignored and contain valid credentials.

### Step (c): Run provider self-check
```powershell
python scripts/provider_selfcheck.py
```
Verify that all configured providers pass or skip without any `FAIL`.

### Step (d): Record provider responses
Run the recording script (optionally passing a harmless test APK):
```powershell
python scripts/record_provider_responses.py
# Or with a harmless APK:
# python scripts/record_provider_responses.py --apk path\to\harmless.apk
```

### Step (e): Secrets check on recorded fixtures
Verify no secret keys or authorization headers were recorded to disk:
```powershell
Select-String -Path tests\fixtures\providers\* -Pattern "api-key|apikey|Authorization" -Recurse
```
This command must print nothing.

### Step (f): Review summary, stage fixtures, and commit
Review `tests/fixtures/providers/RECORDING_SUMMARY.md` and `MANIFEST.sha256`:
```powershell
git add tests/fixtures/providers
git commit -m "day5: recorded responses"
```
Once committed, re-run the agent prompt to begin Phase 2 (adapters and pipeline integration).
