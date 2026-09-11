const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const OUT_DIR = path.join(__dirname, '..', '..', 'docs', 'screenshots');
fs.mkdirSync(OUT_DIR, { recursive: true });

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();

  // 1. Login page
  await page.goto('http://localhost:5173/login');
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path: path.join(OUT_DIR, 'login.png') });
  console.log('✓ login.png');

  // 2. Login and go to dashboard
  await page.fill('input[type="email"]', 'admin@example.com');
  await page.fill('input[type="password"]', 'admin123');
  await page.click('button[type="submit"]');
  await page.waitForURL('**/', { timeout: 10000 });
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(OUT_DIR, 'dashboard.png'), fullPage: true });
  console.log('✓ dashboard.png');

  // 3. Scans list
  await page.goto('http://localhost:5173/scans');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(OUT_DIR, 'scans-list.png') });
  console.log('✓ scans-list.png');

  // 4. Scan detail top
  await page.goto('http://localhost:5173/scans/1');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(OUT_DIR, 'scan-detail-top.png') });
  console.log('✓ scan-detail-top.png');

  // 5. Scroll to show more findings
  await page.evaluate(() => document.querySelector('main').scrollTop = 280);
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(OUT_DIR, 'scan-findings.png') });
  console.log('✓ scan-findings.png');

  // 6. Users page
  await page.goto('http://localhost:5173/users');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(OUT_DIR, 'users.png') });
  console.log('✓ users.png');

  await browser.close();
  console.log('\nDone! All screenshots in docs/screenshots/');
})();
