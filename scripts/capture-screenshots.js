const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const OUT_DIR = path.join(__dirname, '..', 'docs', 'screenshots');
fs.mkdirSync(OUT_DIR, { recursive: true });

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();

  // ── 1. Login page ────────────────────────────────────────────────────────────
  await page.goto('http://localhost:5173/login');
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: path.join(OUT_DIR, 'login.png'), fullPage: false });
  console.log('✓ login.png');

  // ── 2. Log in ─────────────────────────────────────────────────────────────────
  await page.fill('input[type="email"]', 'admin@example.com');
  await page.fill('input[type="password"]', 'admin123');
  await page.click('button[type="submit"]');
  await page.waitForURL('**/dashboard', { timeout: 10000 });
  await page.waitForLoadState('networkidle');

  // ── 3. Dashboard – full page scroll capture ───────────────────────────────────
  await page.screenshot({ path: path.join(OUT_DIR, 'dashboard.png'), fullPage: true });
  console.log('✓ dashboard.png');

  // ── 4. Scans list ─────────────────────────────────────────────────────────────
  await page.goto('http://localhost:5173/scans');
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: path.join(OUT_DIR, 'scans-list.png'), fullPage: false });
  console.log('✓ scans-list.png');

  // ── 5. Scan detail ────────────────────────────────────────────────────────────
  await page.goto('http://localhost:5173/scans/1');
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: path.join(OUT_DIR, 'scan-detail.png'), fullPage: false });
  console.log('✓ scan-detail.png');

  // ── 6. Scroll down & capture expanded finding ─────────────────────────────────
  // Click first finding chevron to expand it
  const chevrons = page.locator('button svg').first();
  try {
    // Try clicking the expand button on first finding row
    await page.locator('[class*="border-red"], [class*="border-orange"], [class*="border-blue"], [class*="border-yellow"]').first().click({ timeout: 3000 });
    await page.waitForTimeout(500);
  } catch (_) {}
  await page.evaluate(() => {
    const main = document.querySelector('main');
    if (main) main.scrollTop = 300;
  });
  await page.waitForTimeout(300);
  await page.screenshot({ path: path.join(OUT_DIR, 'scan-findings.png'), fullPage: false });
  console.log('✓ scan-findings.png');

  // ── 7. Users page ─────────────────────────────────────────────────────────────
  await page.goto('http://localhost:5173/users');
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: path.join(OUT_DIR, 'users.png'), fullPage: false });
  console.log('✓ users.png');

  await browser.close();
  console.log('\nAll screenshots saved to docs/screenshots/');
})();
