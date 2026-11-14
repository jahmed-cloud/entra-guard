# README screenshots

The images in `docs/images/` are taken from a real running stack filled with sample data for a fictional tenant. Retake them after a visible UI change.

Needs: Docker, Python with the engine's requirements installed, Node.js, and Google Chrome (the path is set at the top of `shoot.js`).

```bash
# 1. Run a throwaway stack (see docs/RELEASING.md step 3) with AUTH_ENABLED=true,
#    a LOCAL_ADMIN_PASSWORD, GUID-shaped AZURE_TENANT_ID / AZURE_CLIENT_ID and
#    TARGET_NAME="Contoso (demo)", e.g. on port 3300.
docker compose -p egshot --env-file /path/to/test.env up -d --build

# 2. Fill it with sample data. This DELETES all scan runs and findings in that
#    database, so never point it at a real deployment.
TARGET=$(docker exec entra-guard-db psql -U cspm_user -d cspm -tAc "select id from targets limit 1")
python scripts/screenshots/make_seed.py services/assessment-engine "$TARGET" /tmp/seed.sql
docker exec -i entra-guard-db psql -U cspm_user -d cspm -q < /tmp/seed.sql

# 3. Capture (install the one dependency somewhere outside the repo first:
#    npm i puppeteer-core, then run from that folder or set NODE_PATH).
node scripts/screenshots/shoot.js http://localhost:3300 /path/to/test.env docs/images

# 4. Tear down
docker compose -p egshot --env-file /path/to/test.env down -v
```

`make_seed.py` runs every real check against an empty fake tenant to get genuine check IDs, severities and remediation text, then assigns a fixed-seed pass/fail mix and made-up `@contoso.com` accounts. Nothing in the screenshots comes from a real tenant.

`shoot.js` also writes `dashboard-full.png` and `about.png`, which the README does not use; delete them or leave them out of the commit.

Look at every image before committing. The script prints the number of browser console errors; it should be 0.
