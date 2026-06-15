const { URL } = require('url');

function cleanUrlForCrawler(urlStr) {
  try {
    const parsed = new URL(urlStr);
    const hash = parsed.hash;
    let clean = urlStr.split('?')[0].split('#')[0];
    if (hash && (hash.startsWith('#/') || hash.startsWith('#!/'))) {
      const cleanHash = hash.split('?')[0];
      return clean + cleanHash;
    }
    return clean;
  } catch (e) {
    return urlStr.split('?')[0].split('#')[0];
  }
}

class RecursiveCrawler {
  constructor(log, sessionBridge) {
    this.log = log || [];
    this.sessionBridge = sessionBridge || null;
    this.visited = new Set();
    this.endpoints = []; // Array of { path, fullUrl, method }
    this.maxPages = 15; // Hard limit to prevent crawling forever
  }

  // Parses HTML body to find links and forms (Fallback static parser)
  extractLinksAndForms(html, currentUrl) {
    const found = [];
    const parsedCurrent = new URL(currentUrl);
    const origin = parsedCurrent.origin;

    // 1. Match href links
    const linkRegex = /href=["']([^"']+)["']/gi;
    let match;
    while ((match = linkRegex.exec(html)) !== null) {
      let href = match[1];
      try {
        if (href.startsWith('/') && !href.startsWith('//')) {
          href = origin + href;
        } else if (!href.startsWith('http://') && !href.startsWith('https://')) {
          // Relative link
          href = new URL(href, currentUrl).href;
        }
        
        const parsedHref = new URL(href);
        if (parsedHref.origin === origin) {
          // Same origin link
          const cleanHref = cleanUrlForCrawler(href);
          found.push({ url: cleanHref, type: 'link', method: 'GET' });
        }
      } catch (e) {
        // Ignore parsing errors
      }
    }

    // 2. Match form action paths
    const formRegex = /<form[^>]*action=["']([^"']+)["'][^>]*method=["']([^"']+)["']/gi;
    while ((match = formRegex.exec(html)) !== null) {
      let action = match[1];
      const method = (match[2] || 'GET').toUpperCase();
      try {
        if (action.startsWith('/') && !action.startsWith('//')) {
          action = origin + action;
        } else if (!action.startsWith('http://') && !action.startsWith('https://')) {
          action = new URL(action, currentUrl).href;
        }
        const parsedAction = new URL(action);
        if (parsedAction.origin === origin) {
          found.push({ url: action, type: 'form', method });
        }
      } catch (e) {
        // Ignore
      }
    }

    return found;
  }

  // Runs the crawler (try Playwright first, fall back to HTTP spider)
  async crawl(startUrl, requestFn, maxDepth = 2, useBrowser = false) {
    this.log.push(`[Crawler] Starting crawl for target: ${startUrl} (max depth: ${maxDepth})`);
    
    if (useBrowser) {
      try {
        const { chromium } = require('playwright');
        return await this.crawlWithPlaywright(startUrl, chromium, maxDepth);
      } catch (err) {
        this.log.push(`[Crawler] Playwright is not available or failed to load. Falling back to HTTP recursive crawler. Error: ${err.message}`);
      }
    }

    // HTTP Crawler Fallback
    return await this.crawlWithHttp(startUrl, requestFn, maxDepth);
  }

  // Playwright crawler implementation
  async crawlWithPlaywright(startUrl, chromium, maxDepth) {
    this.log.push(`[Crawler] Launching headless Playwright browser...`);
    const browser = await chromium.launch({ 
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'] 
    });
    
    const context = await browser.newContext({
      ignoreHTTPSErrors: true
    });

    const page = await context.newPage();

    // Hook the session bridge if available
    if (this.sessionBridge) {
      this.sessionBridge.registerPageHooks(page);
      await this.sessionBridge.syncToBrowserContext(context, startUrl);
    }

    const queue = [{ url: startUrl, depth: 0 }];
    const parsedStart = new URL(startUrl);
    const origin = parsedStart.origin;

    while (queue.length > 0) {
      if (this.visited.size >= this.maxPages) {
        this.log.push(`[Crawler] Reached maximum page limit of ${this.maxPages}. Stopping crawl.`);
        break;
      }
      const { url, depth } = queue.shift();
      const cleanUrl = cleanUrlForCrawler(url);

      if (this.visited.has(cleanUrl) || depth > maxDepth) continue;
      this.visited.add(cleanUrl);

      this.log.push(`[Crawler:Browser] Visiting: ${url} at depth ${depth}`);
      
      try {
        await page.goto(url, { waitUntil: 'networkidle', timeout: 10000 });
        
        // Sync local storage dynamic tokens back to HTTP scanner
        if (this.sessionBridge) {
          await this.sessionBridge.syncFromBrowserStorage(page);
        }

        const path = new URL(url).pathname;
        this.endpoints.push({ path, fullUrl: url, method: 'GET' });

        // Extract client-side links
        const links = await page.evaluate(() => {
          return Array.from(document.querySelectorAll('a'))
            .map(a => a.href)
            .filter(href => href && href.startsWith(window.location.origin));
        });

        // Extract forms
        const forms = await page.evaluate(() => {
          return Array.from(document.querySelectorAll('form')).map(f => ({
            action: f.action || window.location.href,
            method: f.method || 'GET'
          }));
        });

        // Add links to queue
        for (const link of links) {
          const cleanLink = cleanUrlForCrawler(link);
          if (!this.visited.has(cleanLink)) {
            queue.push({ url: link, depth: depth + 1 });
          }
        }

        // Add form actions to endpoints
        for (const form of forms) {
          try {
            const formUrl = new URL(form.action, url).href;
            const formPath = new URL(formUrl).pathname;
            this.endpoints.push({
              path: formPath,
              fullUrl: formUrl,
              method: form.method.toUpperCase()
            });
          } catch (e) {}
        }

      } catch (err) {
        this.log.push(`[Crawler:Browser] Failed to visit ${url}: ${err.message}`);
      }
    }

    await browser.close();
    this.log.push(`[Crawler] Finished Playwright crawl. Discovered ${this.endpoints.length} unique actions.`);
    return this.endpoints;
  }

  // HTTP-based recursive spider implementation
  async crawlWithHttp(startUrl, requestFn, maxDepth) {
    const queue = [{ url: startUrl, depth: 0 }];
    const parsedStart = new URL(startUrl);
    const origin = parsedStart.origin;

    const headers = this.sessionBridge && this.sessionBridge.sessionManager
      ? this.sessionBridge.sessionManager.getHeaders()
      : {};

    while (queue.length > 0) {
      if (this.visited.size >= this.maxPages) {
        this.log.push(`[Crawler] Reached maximum page limit of ${this.maxPages}. Stopping crawl.`);
        break;
      }
      const { url, depth } = queue.shift();
      const cleanUrl = cleanUrlForCrawler(url);

      if (this.visited.has(cleanUrl) || depth > maxDepth) continue;
      this.visited.add(cleanUrl);

      this.log.push(`[Crawler:HTTP] Fetching: ${url} at depth ${depth}`);

      const res = await requestFn(url, {
        method: 'GET',
        headers
      });

      if (res.status >= 200 && res.status < 300) {
        const path = new URL(url).pathname;
        this.endpoints.push({ path, fullUrl: url, method: 'GET' });

        const extracted = this.extractLinksAndForms(res.body, url);
        
        for (const item of extracted) {
          if (item.type === 'link') {
            const cleanLink = item.url.split('?')[0].split('#')[0];
            if (!this.visited.has(cleanLink)) {
              queue.push({ url: item.url, depth: depth + 1 });
            }
          } else if (item.type === 'form') {
            const formPath = new URL(item.url).pathname;
            this.endpoints.push({
              path: formPath,
              fullUrl: item.url,
              method: item.method
            });
          }
        }
      } else {
        this.log.push(`[Crawler:HTTP] Failed to fetch ${url}. Status code: ${res.status}`);
      }
    }

    this.log.push(`[Crawler] Finished HTTP crawl. Discovered ${this.endpoints.length} unique actions.`);
    return this.endpoints;
  }
}

module.exports = { RecursiveCrawler };
