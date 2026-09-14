// Regenerates the README screenshots in docs/screenshots/.
//
// Requires the backend and frontend dev servers running locally
// (http://localhost:8000 and http://localhost:5173) with demo data loaded —
// see scripts/seed_demo_data.py — and Playwright installed:
//   npm install -D playwright && npx playwright install chromium
//
// The app has no login/auth (see README "No login required"), so there is
// no login step — this only visits the routes that actually exist in
// frontend/src/App.jsx: "/", "/scans", "/scans/:id".
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const OUT_DIR = path.join(__dirname, '..', 'docs', 'screenshots');
fs.mkdirSync(OUT_DIR, { recursive: true });

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();

  // ── 1. Dashboard ("/") – full page ────────────────────────────────────────────
  await page.goto('http://localhost:5173/');
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: path.join(OUT_DIR, 'dashboard.png'), fullPage: true });
  console.log('✓ dashboard.png');

  // ── 2. Scans list ("/scans") ──────────────────────────────────────────────────
  await page.goto('http://localhost:5173/scans');
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: path.join(OUT_DIR, 'scans-list.png'), fullPage: false });
  console.log('✓ scans-list.png');

  // ── 3. Scan detail ("/scans/1") – top of page ─────────────────────────────────
  // Assumes scan #1 has findings — seed with scripts/seed_demo_data.py first.
  await page.goto('http://localhost:5173/scans/1');
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: path.join(OUT_DIR, 'scan-detail-top.png'), fullPage: false });
  console.log('✓ scan-detail-top.png');

  // ── 4. Scan detail – scrolled to show a mix of severities/rules ──────────────
  await page.evaluate(() => {
    const main = document.querySelector('main');
    if (main) main.scrollTop = main.scrollHeight;
  });
  await page.waitForTimeout(300);
  await page.screenshot({ path: path.join(OUT_DIR, 'scan-findings.png'), fullPage: false });
  console.log('✓ scan-findings.png');

  await browser.close();
  console.log('\nAll screenshots saved to docs/screenshots/');
})();
