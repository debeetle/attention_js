import { setVapidDetails, sendNotification } from './pwanotify.js';
import { buildQWeatherAuthorizationHeader } from './qweather-jwt.js';
import { XMLParser } from 'fast-xml-parser';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const SHANGHAI_TZ = 'Asia/Shanghai';
const HISTORY_KEY = 'items';
const HISTORY_LIMIT = 200;
const HISTORY_RETENTION_MS = 3 * 24 * 60 * 60 * 1000;
const QWEATHER_API_HOST = 'mh7mdaq86q.re.qweatherapi.com';

const DEFAULT_RSS_SOURCES = [
  { sourceKey: 'picture of the day', feedUrl: 'https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=potd&feedformat=atom',
    crons: ['15 0 * * *'] },
  { sourceKey: 'on this day', feedUrl: 'https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=onthisday&feedformat=atom',
    crons: ['15 0 * * *'] },
  { sourceKey: 'do you know', feedUrl: 'https://zh.wikipedia.org/w/api.php?action=featuredfeed&feed=dyk&feedformat=atom',
    crons: ['15 0 * * *'] },
  { sourceKey: 'sspai', feedUrl: 'https://sspai.com/feed',
    includeKeywords: [], excludeKeywords: [],
    crons: ['0 0,4,8,12 * * *'] },
  { sourceKey: 'ithome', feedUrl: 'https://www.ithome.com/rss/',
    includeKeywords: ["苹果", "微软", "谷歌"], excludeKeywords: ['追觅', '鸿蒙智', '鼠标', '电影票房', '荣耀', '券', '智界','问界', '尊界', '抖音', '车型', '补贴', '联名', '月卡', '年卡'],
    crons: ['0 0,4,8,12 * * *'] }
];

const FEED_XML_PARSER = new XMLParser({
  ignoreAttributes: false, attributeNamePrefix: '',
  trimValues: false, parseTagValue: false, parseAttributeValue: false,
  processEntities: false, cdataPropName: '__cdata',
  stopNodes: ['*.summary', '*.description', '*.content']
});

// Tags whose content is kept but the tag itself is removed (unwrap).
const UNWRAP_TAGS = new Set(['b', 'strong', 'em']);
// Tags that are removed entirely including children.
const DROP_TAGS = new Set(['script', 'link', 'img']);
const DROP_ATTRIBUTES = new Set(['style', 'class', 'title']);

const SOURCE_DISPLAY_NAMES = {
  'picture of the day': '[Potd]', 'on this day': '[Otd]', 'do you know': '[Dyk]',
  'sspai': '[Pai]', 'ithome': '[IThome]', 'weather': '[Weather]'
};

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------
function b64ToU8(b64) {
  const bin = atob(b64), arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function aesGcmEncrypt(rawKeyB64, plaintext) {
  const key = await crypto.subtle.importKey('raw', b64ToU8(rawKeyB64), 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  return { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}

async function aesGcmDecrypt(rawKeyB64, ivArr, ctArr) {
  const key = await crypto.subtle.importKey('raw', b64ToU8(rawKeyB64), 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(ivArr) }, key, new Uint8Array(ctArr).buffer);
  return new TextDecoder().decode(pt);
}

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacHex(secret, data, hash = 'SHA-256') {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: { name: hash } }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// General utilities
// ---------------------------------------------------------------------------
const splitCsv = v => (v || '').split(',').map(s => s.trim()).filter(Boolean);

function toAbsoluteUrl(url, base = '') {
  if (!url) return '';
  if (url.startsWith('//')) return `https:${url}`;
  try { return base ? new URL(url, base).toString() : new URL(url).toString(); }
  catch { return url; }
}

function safeOrigin(url) {
  try { return url ? new URL(url).origin : ''; }
  catch { return ''; }
}

function truncateToSentence(text, maxLen = 5) {
  const s = (text || '').replace(/\s+/g, ' ').trim();
  if (s.length <= maxLen) return s;
  const cut = s.slice(0, maxLen);
  const end = Math.max(cut.lastIndexOf('. '), cut.lastIndexOf('! '), cut.lastIndexOf('? '),
    cut.lastIndexOf('。'), cut.lastIndexOf('！'), cut.lastIndexOf('？'));
  return end >= 20 ? `${cut.slice(0, end + 1).trim()}...` : `${cut.trim()}...`;
}

const safeEqual = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
};

const formEncode = params => Object.entries(params)
  .filter(([, v]) => v !== undefined && v !== null && String(v).length > 0)
  .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&');

function isOriginAllowed(request, allowedList) {
  if (!allowedList || allowedList.length === 0) return true;
  const origin = request.headers.get('Origin') || request.headers.get('Referer') || '';
  return origin && allowedList.some(item => origin.startsWith(item));
}

// ---------------------------------------------------------------------------
// VAPID
// ---------------------------------------------------------------------------
function initializeVapid(env) {
  if (env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY) {
    setVapidDetails(env.VAPID_SUBJECT || 'mailto:nobody@example.com',
      env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY);
  }
}

// ---------------------------------------------------------------------------
// HTML sanitization (HTMLRewriter)
// ---------------------------------------------------------------------------
function sanitizeHref(href, baseUrl) {
  const url = toAbsoluteUrl(href || '', baseUrl);
  try { const u = new URL(url); if (u.protocol === 'http:' || u.protocol === 'https:') return u.toString(); }
  catch { /* invalid */ }
  return '';
}

/**
 * HTMLRewriter element handler: strips disallowed tags/attrs,
 * unwraps unknown tags, sanitises <a href>.
 */
class SummaryElementSanitizer {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
  }

  element(element) {
    const tag = (element.tagName || '').toLowerCase();
    if (!tag) return;

    if (DROP_TAGS.has(tag)) {
      element.remove();
      return;
    }

    if (UNWRAP_TAGS.has(tag)) {
      element.removeAndKeepContent();
      return;
    }

    for (const name of DROP_ATTRIBUTES) {
      if (element.getAttribute(name) !== null) {
        element.removeAttribute(name);
      }
    }

    if (tag === 'a') {
      const href = sanitizeHref(element.getAttribute('href') || '', this.baseUrl);
      if (href) {
        element.setAttribute('href', href);
      } 
    }
  }
}

/** HTMLRewriter document handler: strips HTML comments. */
// class CommentFilter {
//   comments(comment) { comment.remove(); }
// }

/**
 * Parse raw summary HTML, sanitise it, and optionally truncate to
 * `maxSentences` (0 = no truncation).
 */
async function sanitizeSummaryHtml(rawHtml, fallbackText, baseUrl = '', sourceKey = '', maxSentences = 3) {
  if (!rawHtml) return fallbackText ? `<p>${fallbackText}</p>` : '';

  // Pre-clean first, then decode entities, then filter tags/attrs via HTMLRewriter.
  // This keeps responsibilities separate and avoids recreating filtered tags after sanitize.
  const preCleaned = (rawHtml || '')
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s*['"`]*\s*UNIQ--[\w-]+-QINU\s*['"`]*\s*/g, ' ')
    .replace(/\s+/g, ' ').trim();
  const decoded = decodeXmlEntities(preCleaned);

  let safe;
  try {
    safe = await new HTMLRewriter()
      .on('*', new SummaryElementSanitizer(baseUrl))
    //   .onDocument(new CommentFilter())
      .transform(new Response(decoded, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }))
      .text();
  } catch { return fallbackText ? `<p>${fallbackText}</p>` : ''; }

  safe = (safe || '').trim();
  if (!safe) return fallbackText ? `<p>${fallbackText}</p>` : '';

  // Wikipedia featured-content feeds have structured blurbs that
  // should be shown in full rather than truncated to N sentences.
  if (sourceKey === 'on this day' || sourceKey === 'picture of the day' || maxSentences <= 0) return safe;

  return truncateSanitizedHtml(safe, maxSentences) || safe;
}

/**
 * Truncate safe HTML after `maxSentences` sentence-ending characters,
 * closing any open tags.
 */
function truncateSanitizedHtml(html, maxSentences) {
  let out = '', sentences = 0, inTag = false;
  const stack = [];

  for (let i = 0; i < html.length; i++) {
    const ch = html[i];
    out += ch;

    if (inTag) {
      if (ch === '>') {
        inTag = false;
        const tagText = out.slice(out.lastIndexOf('<') + 1, out.length - 1).trim();
        if (!tagText || tagText[0] === '!' || tagText[0] === '?') continue;
        if (tagText[0] === '/') {
          const name = tagText.slice(1).split(/\s+/)[0].toLowerCase();
          const idx = stack.lastIndexOf(name);
          if (idx >= 0) stack.splice(idx, 1);
        } else if (!tagText.endsWith('/')) {
          const name = tagText.replace(/\/$/, '').split(/\s+/)[0].toLowerCase();
          if (name !== 'br') stack.push(name);
        }
      }
      continue;
    }

    if (ch === '<') { inTag = true; continue; }

    // Sentence terminators — skip periods that serve non-sentence roles
    if (!/[.!?。！？]/.test(ch)) continue;

    if (ch === '.' && i > 0) {
      const prev = html[i - 1];
      const next = i + 1 < html.length ? html[i + 1] : '';

      // Decimal point (e.g. "3.14")
      if (/\d/.test(prev) && /\d/.test(next)) continue;
      // Abbreviation between uppercase letters (e.g. "D.C", "U.S.")
      if (/[A-Z]/.test(prev) && /[A-Z]/.test(next)) continue;
      // Abbreviation period then comma (e.g. "D.C.,")
      if (/[A-Z]/.test(prev) && next === ',') continue;
      // Ellipsis or consecutive periods (e.g. "...")
      if (next === '.') continue;
    }

    if (++sentences < maxSentences) continue;

    while (stack.length) out += `</${stack.pop()}>`;
    return out.trim();
  }
  return html.trim();
}

// ---------------------------------------------------------------------------
// RSS / Atom feed parsing (fast-xml-parser)
// ---------------------------------------------------------------------------
const asArray = v => (v == null ? [] : Array.isArray(v) ? v : [v]);

/** Extract raw text from fast-xml-parser output (strings, arrays, #text, __cdata). */
function xmlText(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(xmlText).filter(Boolean).join(' ');
  if (typeof value === 'object') return String(value['#text'] || value.__cdata || '');
  return '';
}

/** Decode common XML/HTML entities and numeric character references. */
function decodeXmlEntities(str) {
  str = str.replace(/&amp;#160;/g, '&#160;');
  if (!str) return '';
  const named = {
    nbsp: '\u00A0', hellip: '\u2026', mdash: '\u2014', ndash: '\u2013',
    lsquo: '\u2018', rsquo: '\u2019', ldquo: '\u201C', rdquo: '\u201D',
    laquo: '\u00AB', raquo: '\u00BB', apos: "'",
    amp: '&', lt: '<', gt: '>', quot: '"'
  };

  return String(str).replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (m, code) => {
    // if (!code) return m;
    if (code[0] === '#') {
      if (code[1] === 'x' || code[1] === 'X') return String.fromCodePoint(parseInt(code.slice(2), 16));
      return String.fromCodePoint(Number(code.slice(1)));
    }
    const key = code.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(named, key)) return named[key];
    return m;
  });
}

/** Extract raw HTML from fast-xml-parser output (strings, arrays, #text, __cdata). */
function xmlHtml(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(xmlHtml).filter(Boolean).join('');
  if (typeof value === 'object') {
        if (typeof value.__cdata === 'string') return value.__cdata;
        if (typeof value['#text'] === 'string') return value['#text'];
  }
  return '';
}

/** Resolve the best link from an Atom/RSS <link> node. */
function resolveFeedLink(linkNode, baseUrl = '') {
  for (const link of asArray(linkNode)) {
    if (typeof link === 'object' && link.href) {
      const href = xmlText(link.href).trim(), rel = xmlText(link.rel).trim().toLowerCase();
      if (href && (!rel || rel === 'alternate')) return toAbsoluteUrl(href, baseUrl);
    } else {
      const href = xmlText(link).trim();
      if (href) return toAbsoluteUrl(href, baseUrl);
    }
  }
  return '';
}

/** Extract the first <img> src from an HTML snippet using regex. */
function extractImageUrl(html, baseUrl = '') {
  if (!html) return '';
  const normalizedHtml = decodeXmlEntities(String(html))
    .replace(/\\\//g, '/')
    .replace(/\\"/g, '"');
  const imgMatch = normalizedHtml.match(/<img[^>]+src=["']([^"']+)["'][^>]*>/i);
  if (imgMatch) return toAbsoluteUrl(imgMatch[1], baseUrl);
  const m = normalizedHtml.match(/<media:(content|thumbnail)[^>]*url=["']([^"']+)["'][^>]*\/?>/i);
  return m ? toAbsoluteUrl(m[2], baseUrl) : '';
}

function parseFeedItemBase(itemNode, feedBaseUrl, sourceKey) {
  const isIthome = sourceKey === 'ithome';
  const title = xmlText(itemNode.title).replace(/<[^>]+>/g, '').trim();
  const link = resolveFeedLink(itemNode.link, feedBaseUrl) || toAbsoluteUrl(xmlText(itemNode.link).trim(), feedBaseUrl);
  const itemId = xmlText(itemNode.id || itemNode.guid).trim() || link;
  const publishedAt = xmlText(itemNode.updated || itemNode.published || itemNode.pubDate).trim();
  const summaryHtmlNode = xmlHtml(itemNode.summary);
  const contentHtmlNode = xmlHtml(itemNode.content);
  const descriptionHtmlNode = xmlHtml(itemNode.description);
  const rawHtml = isIthome ? '' : (summaryHtmlNode || contentHtmlNode || descriptionHtmlNode);
  const imageScanHtml = [summaryHtmlNode, contentHtmlNode, descriptionHtmlNode].filter(Boolean).join(' ');
  const imageUrl = extractImageUrl(imageScanHtml || rawHtml, feedBaseUrl || link);
  const description = isIthome ? title : truncateToSentence(rawHtml.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim(), 180);
  return { title, link, itemId, publishedAt, rawHtml, imageUrl, description };
}

async function parseIthomeItem(base) {
  return {
    title: base.title, link: base.link, description: base.description, summaryText: base.description,
    summaryHtml: '', imageUrl: base.imageUrl, itemId: base.itemId, publishedAt: base.publishedAt
  };
}

async function parsePotdItem(base, sourceKey) {
  let summaryHtml = await sanitizeSummaryHtml(base.rawHtml, base.description, base.link, sourceKey);
  try {
    summaryHtml = await new HTMLRewriter()
      .on('a', { element: element => element.removeAndKeepContent() })
      .transform(new Response(summaryHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }))
      .text();
  } catch { /* keep sanitized summary */ }
    function firstSentence(text) {
        const s = (text || '').replace(/\s+/g, ' ').trim();
        if (!s) return '';
        const i = s.search(/[.!?。！？]/);
        return (i >= 0 ? s.slice(0, i + 1) : s).trim();
    }
  const description = firstSentence(summaryHtml.replace(/<[^>]+>/g, ' '));
  return {
    title: base.title, link: base.link, description, summaryText: description,
    summaryHtml, imageUrl: base.imageUrl, itemId: base.itemId, publishedAt: base.publishedAt
  };
}

async function parseOnThisDayItem(base, sourceKey) {
  let summaryHtml = await sanitizeSummaryHtml(base.rawHtml, base.description, base.link, sourceKey);
  const heading = summaryHtml.match(/<p\b[^>]*>[\s\S]*?<\/p>/i)?.[0] || '';
  const title = decodeXmlEntities(heading.replace(/<[^>]+>/g, '')).replace(/\u00a0/g, ' ').trim();
  const listBody = summaryHtml.match(/<ul\b[^>]*>([\s\S]*?)<\/ul>/i)?.[1] || '';
  const entries = [...listBody.matchAll(/<li\b[^>]*>[\s\S]*?<\/li>/gi)].map(m => m[0]);

  if (entries.length) {
    const selected = (entries.find(entry => /\([^)]*\b(pictured|depicted)\b[^)]*\)/i.test(entry)) || entries[0]).trim();
    const text = selected.replace(/^<li\b[^>]*>/i, '').replace(/<\/li>$/i, '').trim();
    summaryHtml = text;
  }

  return {
    title, link: base.link, description: base.description, summaryText: base.description,
    summaryHtml, imageUrl: base.imageUrl, itemId: base.itemId, publishedAt: base.publishedAt
  };
}

async function parseGenericFeedItem(base, sourceKey) {
  const summaryHtmlRaw = await sanitizeSummaryHtml(base.rawHtml, base.description, base.link, sourceKey);
  return {
    title: base.title, link: base.link, description: base.description, summaryText: base.description,
    summaryHtml: summaryHtmlRaw, imageUrl: base.imageUrl, itemId: base.itemId, publishedAt: base.publishedAt
  };
}

const FEED_ITEM_PARSERS = {
  'ithome': parseIthomeItem,
  'picture of the day': parsePotdItem,
  'on this day': parseOnThisDayItem
};

/** Parse one <entry> / <item> node into a plain object. */
async function parseFeedItem(itemNode, feedBaseUrl, source) {
  const sourceKey = (source?.sourceKey || '').toLowerCase();
  const base = parseFeedItemBase(itemNode, feedBaseUrl, sourceKey);
  const parser = FEED_ITEM_PARSERS[sourceKey] || parseGenericFeedItem;
  return parser(base, sourceKey);
}

/** Parse a complete RSS/Atom feed text, return items sorted oldest-first. */
async function parseFeedItems(feedText, source = null) {
  const parsed = FEED_XML_PARSER.parse(feedText);
  const root = parsed.feed || parsed.rss?.channel;
  if (!root) return null;

  const baseUrl = resolveFeedLink(root.link || root.atomLink);
  const rawItems = root.entry || root.item || [];
  const items = (await Promise.all(asArray(rawItems).map(n => parseFeedItem(n, baseUrl, source))))
    .filter(it => it && it.title);

  if (!items.length) return null;
  items.sort((a, b) => (Date.parse(a.publishedAt || 0)) - (Date.parse(b.publishedAt || 0)));
  return items;
}

async function parseLatestFeedItem(feedText, source = null) {
  const items = await parseFeedItems(feedText, source);
  return items?.at(-1) || null;
}

// ---------------------------------------------------------------------------
// Notification building
// ---------------------------------------------------------------------------
function buildNotificationText(item) {
  const html = item.summaryHtml || '';
  const sourceKey = (item.sourceKey || '').toLowerCase();
  if (sourceKey === 'picture of the day' && item.description) return truncateToSentence(item.description, 10);

  let text = '';
  if (sourceKey === 'on this day') {
    const pMatch = html.match(/<p\b[^>]*>([\s\S]*?)<\/p>/i);
    const ulMatch = html.match(/<ul\b[^>]*>([\s\S]*?)<\/ul>/i);
    const parts = [];
    if (pMatch) parts.push(pMatch[1].replace(/<[^>]+>/g, '').trim());
    if (ulMatch) {
      const lis = [...ulMatch[1].matchAll(/<li\b[^>]*>([\s\S]*?)<\/li>/gi)].map(m => m[1].replace(/<[^>]+>/g, '').trim());
      if (lis.length) parts.push(lis.join(' · '));
    }
    text = parts.join(' ') || html.replace(/<[^>]+>/g, '').trim();
  } else {
    const lis = [...html.matchAll(/<li\b[^>]*>([\s\S]*?)<\/li>/gi)].map(m => m[1].replace(/<[^>]+>/g, '').trim());
    text = lis.length ? lis.join(' · ') : html.replace(/<[^>]+>/g, '').trim();
  }

  text = text.replace(/["""]/g, '').replace(/\s+([,.;:!?])/g, '$1')
    .replace(/\(\s+/g, '(').replace(/\s+\)/g, ')').replace(/\s+/g, ' ').trim();

  return truncateToSentence(text, 10);
}

function buildNotificationPayload(historyItem) {
  const display = SOURCE_DISPLAY_NAMES[(historyItem.sourceKey || '').toLowerCase()] || '';
  const title = display
    ? `${display} ${historyItem.title}`
    : (historyItem.title);

  return {
    web_push: 8030,
    notification: {
      title,
      body: historyItem.notificationText,
      silent: false,
      app_badge: '1',
      ...(historyItem.link ? { navigate: historyItem.link } : {})
    }
  };
}

// ---------------------------------------------------------------------------
// State management (KV)
// ---------------------------------------------------------------------------
async function getStateJson(env, key) {
  const raw = await env.SUBS.get(key);
  return raw ? JSON.parse(raw) : null;
}
async function putStateJson(env, key, value) { await env.SUBS.put(key, JSON.stringify(value)); }

const sourceLastKey = sk => `pointer:${sk}`;

function deriveItemKey(item) {
  return item.itemId || item.link || `${item.title}::${item.publishedAt || ''}`;
}

function getSourceConfig(sourceKey) {
  return DEFAULT_RSS_SOURCES.find(f => f.sourceKey === sourceKey) || null;
}

async function appendHistoryItem(env, item) {
  const now = Date.now();
  const history = ((await getStateJson(env, HISTORY_KEY)) || [])
    .filter(it => it && it.createdAt && (now - Date.parse(it.createdAt)) <= HISTORY_RETENTION_MS);
  const next = [item, ...history.filter(it => it.id !== item.id)]
    .sort((a, b) => (Date.parse(b.createdAt || 0)) - (Date.parse(a.createdAt || 0)))
    .slice(0, HISTORY_LIMIT);
  await putStateJson(env, HISTORY_KEY, next);
  return next;
}

// ---------------------------------------------------------------------------
// Feed processing
// ---------------------------------------------------------------------------

/** Return items in `items` that appear after `lastKey` (by item key equality). */
function getUnseenItems(items, lastKey = '') {
  if (!lastKey) return asArray(items).filter(Boolean);
  const sorted = asArray(items).filter(Boolean);
  const idx = sorted.findIndex(it => deriveItemKey(it) === lastKey);
  return idx < 0 ? sorted : sorted.slice(idx + 1);
}

/** Check excludeKeywords – return true if item should be silently dropped. */
function shouldDiscardItem(sourceKey, item) {
  const cfg = getSourceConfig(sourceKey);
  if (!cfg || !Array.isArray(cfg.excludeKeywords) || !cfg.excludeKeywords.length) return false;
  const text = [item.title, item.summaryText, item.description].filter(Boolean).join(' ').toLowerCase();
  return cfg.excludeKeywords.some(kw => text.includes(kw.toLowerCase()));
}

/** Check includeKeywords – return true if item is allowed to trigger a notification. */
function matchesFeedFilter(sourceKey, item) {
  const cfg = getSourceConfig(sourceKey);
  if (!cfg || !Array.isArray(cfg.includeKeywords) || !cfg.includeKeywords.length) return true;
  const text = [item.title, item.summaryText, item.description].filter(Boolean).join(' ').toLowerCase();
  return cfg.includeKeywords.some(kw => text.includes(kw.toLowerCase()));
}

/**
 * Process a single item for a source: deduplicate, filter, persist to history,
 * optionally send notification, and advance the "last seen" cursor.
 */
async function processSourceItem(env, source, item, opts = {}) {
  const { updateLastSeen = true } = opts;
  const key = deriveItemKey(item);
  if (!key) return { skipped: true, reason: 'missing_key', sourceKey: source.sourceKey };

  const lastKey = await env.SUBS.get(sourceLastKey(source.sourceKey));
  if (lastKey === key) return { skipped: true, reason: 'duplicate', sourceKey: source.sourceKey, itemKey: key };

  if (shouldDiscardItem(source.sourceKey, item)) {
    if (updateLastSeen) await env.SUBS.put(sourceLastKey(source.sourceKey), key);
    return { skipped: true, reason: 'excluded', sourceKey: source.sourceKey, itemKey: key };
  }

  const historyItem = {
    id: `${source.sourceKey}:${key}`,
    sourceKey: source.sourceKey,
    title: item.title || '',
    description: item.description || '',
    summaryText: item.summaryText || '',
    summaryHtml: item.summaryHtml || '',
    link: item.link || '',
    imageUrl: item.imageUrl || '',
    publishedAt: item.publishedAt || '',
    createdAt: new Date().toISOString()
  };
  historyItem.notificationText = buildNotificationText(historyItem);
  await appendHistoryItem(env, historyItem);

  if (!matchesFeedFilter(source.sourceKey, item)) {
    if (updateLastSeen) await env.SUBS.put(sourceLastKey(source.sourceKey), key);
    return { skipped: true, reason: 'filtered', sourceKey: source.sourceKey, itemKey: key };
  }

  const result = await sendToAllSubscriptions(env, buildNotificationPayload(historyItem));
  if (updateLastSeen) await env.SUBS.put(sourceLastKey(source.sourceKey), key);
  return { skipped: false, sourceKey: source.sourceKey, itemKey: key, ...result };
}

/** Process a batch of feed items (oldest first). */
async function processFeedItems(env, source, items, opts = {}) {
  const lastKey = opts.lastItemKey || await env.SUBS.get(sourceLastKey(source.sourceKey)) || '';
  const unseen = getUnseenItems(items, lastKey);
  const results = { sourceKey: source.sourceKey, total: unseen.length, processed: 0, skipped: 0, sent: 0, failed: 0, errors: [] };

  for (const item of unseen) {
    const r = await processSourceItem(env, source, item, opts);
    if (r.skipped) { results.skipped++; continue; }
    results.processed++;
    results.sent += r.sent || 0;
    results.failed += r.failed || 0;
    if (r.errors?.length) results.errors.push(...r.errors);
    if ((r.failed || 0) > 0) break;
  }
  return results;
}

/** Fetch & parse a feed URL, then process all unseen items. */
async function processFetchedFeedText(env, source, feedText, opts = {}) {
  const items = await parseFeedItems(feedText, source);
  if (!items?.length) return { skipped: true, reason: 'no_items', sourceKey: source.sourceKey };
  return processFeedItems(env, source, items, opts);
}

/** Fetch a feed URL and return status + text preview. */
async function fetchFeedPreview(feedUrl) {
  const res = await fetch(feedUrl, {
    headers: { 'User-Agent': 'Attention-Worker/1.0', Accept: 'application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.1' }
  });
  const text = await res.text();
  return { status: res.status, contentType: res.headers.get('content-type') || '', text };
}

// ---------------------------------------------------------------------------
// QWeather
// ---------------------------------------------------------------------------
function normalizeApiHost(host) {
  if (!host) return '';
  return /^https?:\/\//i.test(host) ? host.replace(/\/+$/g, '') : `https://${host.replace(/\/+$/g, '')}`;
}

function buildQWeatherSource(env) {
  const location = env.QWEATHER_LOCATION || '';
  const privateKey = env.QWEATHER_PRIVATE_KEY || env.qweather_key || '';
  if (!location || !privateKey) return null;
  return { sourceKey: 'Weather', sourceType: 'weather', location };
}

async function fetchQWeatherHourlyForecast(env, location) {
  const apiHost = normalizeApiHost(QWEATHER_API_HOST);
  const url = new URL('/v7/weather/24h', apiHost);
  url.searchParams.set('location', location);
  const res = await fetch(url.toString(), { headers: { Authorization: await buildQWeatherAuthorizationHeader(env), Accept: 'application/json' } });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`QWeather request failed: ${res.status}`);
  if (!data || data.code !== '200' || !Array.isArray(data.hourly)) throw new Error(`QWeather response invalid: ${data?.code || 'unknown'}`);
  return data;
}

function buildRainAlertItem(forecast) {
  const hourly = (forecast.hourly || []).slice(0, 6);
  const rainy = hourly.find(h => {
    const precip = Number(h.precip || 0), pop = Number(h.pop || 0);
    return precip > 0 || (pop > 0 && /(雨|雷阵雨|阵雨|rain|shower|drizzle|thunder|storm)/i.test(String(h.text || '')));
  });
  if (!rainy) return null;

  let fxTime;
  try {
    fxTime = new Intl.DateTimeFormat('en-GB', { timeZone: SHANGHAI_TZ, hour: '2-digit', minute: '2-digit', hour12: false, month: 'numeric', day: 'numeric' })
      .format(new Date(rainy.fxTime));
  } catch { fxTime = rainy.fxTime || ''; }

  const details = [rainy.text, rainy.pop ? `PoP ${rainy.pop}%` : '', Number(rainy.precip || 0) > 0 ? `Precip ${rainy.precip} mm` : ''].filter(Boolean).join(' · ');
  const summary = `Weather expected by ${fxTime}. ${details}`.trim();

  return { title: 'Weather', description: summary, summaryText: summary, summaryHtml: `<p>${summary}</p>`,
    link: '', imageUrl: '', itemId: rainy.fxTime, publishedAt: rainy.fxTime };
}

async function processQWeatherRainAlert(env) {
  const source = buildQWeatherSource(env);
  if (!source) return { skipped: true, reason: 'missing_qweather_location' };
  const forecast = await fetchQWeatherHourlyForecast(env, source.location);
  const item = buildRainAlertItem(forecast);
  if (!item) return { skipped: true, reason: 'no_rain_6h', sourceKey: source.sourceKey };
  return processSourceItem(env, source, item, { updateLastSeen: true });
}

// ---------------------------------------------------------------------------
// Subscription management
// ---------------------------------------------------------------------------
async function listSubscriptions(env) {
  const out = [];
  let cursor;
  for (;;) {
    const page = await env.SUBS.list({ cursor, limit: 1000 });
    for (const key of page.keys || []) {
      if (!/^[0-9a-f]{64}$/i.test(key.name)) continue;
      const stored = await env.SUBS.get(key.name);
      if (!stored) continue;
      try {
        const { iv, ct } = JSON.parse(stored);
        const plain = await aesGcmDecrypt(env.SUBS_ENC_KEY, iv, ct);
        const sub = JSON.parse(plain).sub;
        if (sub?.endpoint) out.push(sub);
      } catch { /* skip corrupt entries */ }
    }
    if (!page.list_complete) { cursor = page.cursor; continue; }
    return out;
  }
}

async function sendToAllSubscriptions(env, payload) {
  const subs = await listSubscriptions(env);
  const results = { total: subs.length, sent: 0, failed: 0, errors: [] };
  for (const sub of subs) {
    try { await sendNotification(sub, JSON.stringify(payload)); results.sent++; }
    catch (e) { results.failed++; results.errors.push({ endpoint: sub.endpoint, error: e?.message || String(e) }); }
  }
  return results;
}

// ---------------------------------------------------------------------------
// WebSub / Webhook verification
// ---------------------------------------------------------------------------
async function verifyWebhookSignature(request, rawBody, secret) {
  if (!secret) return true;
  const sig256 = request.headers.get('x-hub-signature-256') || request.headers.get('x-signature-sha256') || '';
  const sig1 = request.headers.get('x-hub-signature') || request.headers.get('x-signature-sha1') || '';

  if (sig256.startsWith('sha256=')) {
    const expected = await hmacHex(secret, rawBody, 'SHA-256');
    return safeEqual(`sha256=${expected}`, sig256);
  }
  if (sig1.startsWith('sha1=')) {
    const expected = await hmacHex(secret, rawBody, 'SHA-1');
    return safeEqual(`sha1=${expected}`, sig1);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Response helper
// ---------------------------------------------------------------------------
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders }
  });
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const allowedOrigins = splitCsv(env.ALLOWED_ORIGINS);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type,x-api-key,x-hub-signature,x-hub-signature-256,x-signature-sha1,x-signature-sha256'
        }
      });
    }

    initializeVapid(env);

    // --- GET /config ---
    if (request.method === 'GET' && url.pathname === '/config') {
      return json({ vapidPublicKey: env.VAPID_PUBLIC_KEY || '' });
    }

    // --- GET /history ---
    if (request.method === 'GET' && url.pathname === '/history') {
      const now = Date.now();
      const raw = ((await getStateJson(env, HISTORY_KEY)) || [])
        .filter(it => it?.createdAt && (now - Date.parse(it.createdAt)) <= HISTORY_RETENTION_MS)
        .sort((a, b) => (Date.parse(b.createdAt || 0)) - (Date.parse(a.createdAt || 0)));

      // Deduplicate by id (first occurrence wins – already sorted newest-first)
      const seen = new Set();
      const deduped = [];
      for (const it of raw) {
        if (seen.has(it.id)) continue;
        seen.add(it.id);
        deduped.push(it);
      }

      const items = await Promise.all(deduped.map(async it => {
        const sk = it.sourceKey;
        const isIthome = sk === 'ithome';
        const isPotd = sk === 'picture of the day';
        const isOnThisDay = sk === 'on this day';

        // Recompute/normalize summaryHtml from stored value.
        // Keep the same decode order as ingest path: sanitize first, decode inside sanitizer.
        const baseUrl = safeOrigin(it.link);
        const safeSummary = isOnThisDay
          ? (it.summaryHtml || '')
          : (isIthome ? '' : (it.summaryHtml ? await sanitizeSummaryHtml(it.summaryHtml, it.notificationText, baseUrl, sk, 0) : ''));

        // Rebuild notificationText from the normalized summaryHtml (migrates old stored values)
        const description = it.description || '';
        let notificationText = buildNotificationText({ summaryHtml: safeSummary, sourceKey: sk, title: it.title, description });
        notificationText = (notificationText || '').replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
        if (notificationText && !/[.!?。！？…]$/.test(notificationText)) notificationText += '...';

        let imageUrl = isIthome ? '' : (it.imageUrl || '');
        if (!imageUrl && safeSummary) {
          imageUrl = extractImageUrl(safeSummary, baseUrl);
        }
        // Update the deduped item in-place so that the KV gets migrated
        it.description = description;
        it.summaryHtml = safeSummary;
        it.imageUrl = imageUrl;
        it.notificationText = notificationText;

        return {
          id: it.id,
          sourceKey: sk,
          title: it.title || '',
          description,
          summaryText: it.summaryText || it.description || '',
          notificationText,
          summaryHtml: safeSummary,
          link: it.link || '',
          imageUrl,
          publishedAt: it.publishedAt || '',
          createdAt: it.createdAt || ''
        };
      }));

      return json({ ok: true, items });
    }

    // --- POST /subscribe ---
    if (request.method === 'POST' && url.pathname === '/subscribe') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const sub = await request.json();
      if (!sub?.endpoint) return new Response('Bad Request', { status: 400 });

      const key = await sha256hex(sub.endpoint);
      try {
        const existing = await env.SUBS.get(key);
        if (existing) {
          const { iv, ct } = JSON.parse(existing);
          const old = JSON.parse(await aesGcmDecrypt(env.SUBS_ENC_KEY, iv, ct));
          if (old.sub?.endpoint === sub.endpoint &&
              old.sub?.keys?.p256dh === sub.keys?.p256dh &&
              old.sub?.keys?.auth === sub.keys?.auth) {
            return json({ status: 'ok', updated: false });
          }
        }
      } catch { /* proceed to overwrite */ }

      const { iv, ct } = await aesGcmEncrypt(env.SUBS_ENC_KEY, JSON.stringify({ sub, created: Date.now() }));
      await env.SUBS.put(key, JSON.stringify({ iv, ct }));
      return json({ status: 'ok', updated: true });
    }

    // --- POST /unsubscribe ---
    if (request.method === 'POST' && url.pathname === '/unsubscribe') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const body = await request.json();
      if (!body?.endpoint) return new Response('Bad Request', { status: 400 });
      await env.SUBS.delete(await sha256hex(body.endpoint));
      return json({ status: 'deleted' });
    }

    // --- POST /send (admin) ---
    if (request.method === 'POST' && url.pathname === '/send') {
      if ((request.headers.get('x-api-key') || '') !== env.SEND_API_KEY) return new Response('Unauthorized', { status: 401 });
      const body = await request.json();
      if (!body?.endpoint) return new Response('Bad Request', { status: 400 });

      const stored = await env.SUBS.get(await sha256hex(body.endpoint));
      if (!stored) return new Response('Not found', { status: 404 });

      const { iv, ct } = JSON.parse(stored);
      const { sub } = JSON.parse(await aesGcmDecrypt(env.SUBS_ENC_KEY, iv, ct));
      try { await sendNotification(sub, JSON.stringify(body.payload || {})); return json({ ok: true }); }
      catch (e) { return new Response(e?.message || String(e), { status: 500 }); }
    }

    // --- /websub ---
    if (url.pathname === '/websub') {
      if (request.method === 'GET') {
        const mode = url.searchParams.get('hub.mode');
        const challenge = url.searchParams.get('hub.challenge');
        const token = url.searchParams.get('hub.verify_token');
        if (!mode || !challenge) return new Response('Bad Request', { status: 400 });
        if (env.WEBSUB_VERIFY_TOKEN && token !== env.WEBSUB_VERIFY_TOKEN) return new Response('Forbidden', { status: 403 });
        return new Response(challenge, { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }

      if (request.method === 'POST') {
        const rawBody = await request.arrayBuffer();
        if (env.WEBSUB_SECRET && !(await verifyWebhookSignature(request, rawBody, env.WEBSUB_SECRET))) {
          return new Response('Unauthorized', { status: 401 });
        }
        const fallbackUrl = url.searchParams.get('hub.topic') || '';
        const text = new TextDecoder().decode(rawBody);
        const work = processFetchedFeedText(env, { sourceKey: fallbackUrl ? `websub:${fallbackUrl}` : 'websub:unknown', sourceType: 'websub' }, text, { updateLastSeen: true });
        ctx?.waitUntil?.(work);
        return new Response(null, { status: 204 });
      }
      return new Response('Method Not Allowed', { status: 405 });
    }

    // --- POST /websub/subscribe ---
    if (request.method === 'POST' && url.pathname === '/websub/subscribe') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const body = await request.json().catch(() => ({}));
      const hub = body.hub || env.WEBSUB_HUB_URL || '';
      const topic = body.topic || env.WEBSUB_TOPIC || '';
      const callback = body.callback || env.WEBSUB_CALLBACK_URL || `${url.origin}/websub`;
      const secret = body.secret || env.WEBSUB_SECRET || '';
      const lease = body.lease_seconds || env.WEBSUB_LEASE_SECONDS || '864000';
      if (!hub || !topic || !callback) return new Response('Missing hub, topic, or callback URL', { status: 400 });

      const res = await fetch(hub, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formEncode({ 'hub.mode': 'subscribe', 'hub.topic': topic, 'hub.callback': callback, 'hub.secret': secret, 'hub.lease_seconds': lease })
      });
      return json({ ok: res.ok, status: res.status, body: await res.text().catch(() => '') }, res.status);
    }

    // --- POST /websub/unsubscribe ---
    if (request.method === 'POST' && url.pathname === '/websub/unsubscribe') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const body = await request.json().catch(() => ({}));
      const hub = body.hub || env.WEBSUB_HUB_URL || '';
      const topic = body.topic || env.WEBSUB_TOPIC || '';
      const callback = body.callback || env.WEBSUB_CALLBACK_URL || `${url.origin}/websub`;
      if (!hub || !topic || !callback) return new Response('Missing hub, topic, or callback URL', { status: 400 });

      const res = await fetch(hub, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formEncode({ 'hub.mode': 'unsubscribe', 'hub.topic': topic, 'hub.callback': callback })
      });
      return json({ ok: res.ok, status: res.status, body: await res.text().catch(() => '') }, res.status);
    }

    // --- POST /webhook ---
    if (request.method === 'POST' && url.pathname === '/webhook') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const rawBody = await request.arrayBuffer();
      if (env.WEBHOOK_SECRET && !(await verifyWebhookSignature(request, rawBody, env.WEBHOOK_SECRET))) {
        return new Response('Unauthorized', { status: 401 });
      }
      const contentType = request.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) return new Response(null, { status: 204 });

      const body = JSON.parse(new TextDecoder().decode(rawBody));
      if (!body?.title) return new Response(null, { status: 204 });

      const item = {
        title: body.title, description: body.body || '', summaryText: body.body || '',
        summaryHtml: body.bodyHtml || '', link: body.link || '', imageUrl: body.imageUrl || '',
        itemId: body.itemKey || body.id || body.link || '', publishedAt: body.publishedAt || new Date().toISOString()
      };
      const work = processSourceItem(env, { sourceKey: body.sourceKey || 'webhook:default', sourceType: 'webhook' }, item, { updateLastSeen: true });
      ctx?.waitUntil?.(work);
      return new Response(null, { status: 204 });
    }

    // --- GET /rss/preview ---
    if (request.method === 'GET' && url.pathname === '/rss/preview') {
      const feedUrl = url.searchParams.get('url') || env.POLL_URL || '';
      if (!feedUrl) return new Response('Missing feed URL', { status: 400 });
      const preview = await fetchFeedPreview(feedUrl);
      return json({ ok: true, feedUrl, status: preview.status, contentType: preview.contentType, preview: preview.text.slice(0, 4000) });
    }

    // --- POST /rss/send (admin) ---
    if (request.method === 'POST' && url.pathname === '/rss/send') {
      if ((request.headers.get('x-api-key') || '') !== env.SEND_API_KEY) return new Response('Unauthorized', { status: 401 });
      const body = await request.json().catch(() => ({}));
      const feedUrl = body.url || env.POLL_URL || '';
      if (!feedUrl) return new Response('Missing feed URL', { status: 400 });

      const preview = await fetchFeedPreview(feedUrl);
      if (preview.status < 200 || preview.status >= 300) return json({ ok: false, feedUrl, status: preview.status, error: 'Feed fetch failed' }, 502);

      const cfg = DEFAULT_RSS_SOURCES.find(f => f.feedUrl === feedUrl);
      const result = await processFetchedFeedText(env, { sourceKey: cfg?.sourceKey || feedUrl, sourceType: 'rss' }, preview.text, { updateLastSeen: true });
      return json({ ok: !result.skipped && result.failed === 0, feedUrl, ...result }, result.failed === 0 ? 200 : 207);
    }

    // --- Static assets fallback ---
    return env.ASSETS.fetch(request);
  },

  async scheduled(controller, env, ctx) {
    initializeVapid(env);

    if (controller.cron === '0 */1 * * *') {
      ctx?.waitUntil?.(processQWeatherRainAlert(env).catch(e => console.error('Weather check failed', e)));
      return;
    }

    for (const cfg of DEFAULT_RSS_SOURCES) {
      if (!(cfg.crons || []).includes(controller.cron)) continue;

      try {
        const preview = await fetchFeedPreview(cfg.feedUrl);
        if (preview.status < 200 || preview.status >= 300) throw new Error(`Feed fetch failed: ${preview.status}`);
        await processFetchedFeedText(env, { sourceKey: cfg.sourceKey, sourceType: 'rss' }, preview.text, { updateLastSeen: true });
      } catch (e) {
        console.error(`Scheduled failed for ${cfg.sourceKey}`, e);
      }
    }
  }
};
