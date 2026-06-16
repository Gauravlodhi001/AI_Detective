const { chromium } = require('playwright');

class XssDomVerifier {
    constructor(log) {
        this.log = log || [];
    }

    // Generates a unique canary id per test so results can be traced to the exact param/payload
    generateCanaryId() {
        return `xssai${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    }

    // Builds a payload that, if it executes as real script in a real DOM, calls back to window.__xssDetective
    buildCanaryPayload(canaryId) {
        return {
            canaryId,
            // Plain script tag injection (works when reflected directly into HTML, unescaped)
            scriptPayload: `<script>window.__xssDetective=window.__xssDetective||[];window.__xssDetective.push("${canaryId}")</script>`,
            // Event-handler injection (works when reflected into an HTML attribute context)
            imgPayload: `"><img src=x onerror="window.__xssDetective=window.__xssDetective||[];window.__xssDetective.push('${canaryId}')">`,
        };
    }

    // Loads a URL in a real browser context and checks whether the canary actually fired
    async verifyExecution(url, { authHeaders = {}, method = 'GET', timeout = 8000 } = {}) {
        let browser;
        try {
            browser = await chromium.launch({
                headless: true,
                args: ['--no-sandbox', '--disable-setuid-sandbox']
            });
            const context = await browser.newContext({ ignoreHTTPSErrors: true });

            if (authHeaders && Object.keys(authHeaders).length > 0) {
                await context.setExtraHTTPHeaders(authHeaders);
            }

            const page = await context.newPage();

            // Catch the canary firing via a real alert/dialog too (covers alert()-based payloads)
            let dialogFired = false;
            page.on('dialog', async (dialog) => {
                dialogFired = true;
                await dialog.dismiss().catch(() => { });
            });

            this.log.push(`[XssDomVerifier] Navigating to ${url} for DOM execution check...`);
            await page.goto(url, { waitUntil: 'networkidle', timeout }).catch((e) => {
                this.log.push(`[XssDomVerifier] Navigation warning: ${e.message}`);
            });

            const canaryFired = await page.evaluate(() => {
                return Array.isArray(window.__xssDetective) ? window.__xssDetective : [];
            }).catch(() => []);

            await browser.close();
            return { executed: canaryFired.length > 0 || dialogFired, firedCanaries: canaryFired, dialogFired };
        } catch (e) {
            this.log.push(`[XssDomVerifier] Error during DOM verification: ${e.message}`);
            if (browser) await browser.close().catch(() => { });
            return { executed: false, firedCanaries: [], dialogFired: false, error: e.message };
        }
    }
}

module.exports = { XssDomVerifier };