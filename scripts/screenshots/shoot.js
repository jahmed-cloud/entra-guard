// Captures README screenshots from a running EntraGuard stack.
// Usage: node shoot.js <base-url> <env-file> <out-dir>
const fs = require("fs");
const path = require("path");
const puppeteer = require("puppeteer-core");

const [BASE, ENV, OUT] = process.argv.slice(2);
const password = fs.readFileSync(ENV, "utf8").split(/\r?\n/)
  .find(l => l.startsWith("LOCAL_ADMIN_PASSWORD=")).split("=").slice(1).join("=").trim();
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function clickText(page, selector, text, exact = false) {
  const ok = await page.evaluate((selector, text, exact) => {
    const el = [...document.querySelectorAll(selector)].find(e => exact ? e.textContent.trim() === text : e.textContent.includes(text));
    if (el) el.click();
    return !!el;
  }, selector, text, exact);
  if (!ok) throw new Error(`not found: ${selector} "${text}"`);
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await puppeteer.launch({
    executablePath: "C:/Program Files/Google/Chrome/Application/chrome.exe",
    headless: "new",
    args: ["--hide-scrollbars", "--force-color-profile=srgb"],
  });
  const page = await browser.newPage();
  const errors = [];
  page.on("console", m => { if (m.type() === "error") errors.push(m.text()); });
  await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });
  const shot = async (name, opts = {}) => {
    await sleep(900); // let fade-in animations and chart transitions finish
    await page.screenshot({ path: path.join(OUT, name + ".png"), ...opts });
    console.log("saved", name);
  };

  // Login page
  await page.goto(BASE, { waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => document.body.innerText.includes("Local admin"), { timeout: 20000 });
  await clickText(page, "button", "Local admin");
  await page.waitForSelector('input[type="password"]');
  await page.type('input[placeholder="admin"]', "admin");
  await shot("login");
  await page.type('input[type="password"]', password);
  await clickText(page, "button", "Sign in", true);
  await page.waitForFunction(() => document.body.innerText.includes("Run scan"), { timeout: 15000 });
  await page.waitForFunction(() => document.body.innerText.toLowerCase().includes("biggest impact"), { timeout: 15000 });

  // Dashboard: top of page, then the full page
  await shot("dashboard");
  await shot("dashboard-full", { fullPage: true });

  // The "Fix first" card on its own
  const card = await page.evaluateHandle(() => {
    const label = [...document.querySelectorAll("div")].find(d => d.childElementCount === 0 && d.textContent.trim().toLowerCase().startsWith("fix first"));
    return label ? label.parentElement.parentElement : null;
  });
  if (card.asElement()) {
    await card.asElement().scrollIntoView();
    await sleep(500);
    await card.asElement().screenshot({ path: path.join(OUT, "fix-first.png") });
    console.log("saved fix-first");
  }

  for (const [nav, name] of [["Findings", "findings"], ["Compliance", "compliance"], ["Remediation", "remediation"],
                             ["Scan History", "scan-history"], ["Users", "users"], ["About", "about"]]) {
    await clickText(page, "aside nav button", nav);
    await page.evaluate(() => window.scrollTo(0, 0));
    await shot(name);
  }

  // A finding opened, to show remediation detail
  await clickText(page, "aside nav button", "Findings");
  await sleep(600);
  const opened = await page.evaluate(() => {
    const row = [...document.querySelectorAll("main div")].find(d =>
      /^AZURE-[A-Z]+-/.test(d.textContent.trim()) && getComputedStyle(d).cursor === "pointer");
    if (row) row.click();
    return !!row;
  });
  if (opened) await shot("finding-detail");
  else console.log("no clickable finding row found; skipped finding-detail");

  // Phone width
  await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 2, isMobile: true });
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.waitForFunction(() => document.body.innerText.includes("Run scan"), { timeout: 15000 });
  await shot("mobile");

  console.log("console errors:", errors.filter(e => !e.includes("401")).length);
  await browser.close();
})().catch(e => { console.error("FAILED:", e.message); process.exit(1); });
