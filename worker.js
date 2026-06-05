globalThis.Buffer = globalThis.Buffer || class Buffer {
    static isBuffer() { return false; }
    static from(v) { return v; }
};

import { setVapidDetails, sendNotification } from './pwanotify.js';
import { buildQWeatherAuthorizationHeader } from './qweather-jwt.js';
import XMLParser from '@nodable/flexible-xml-parser';
import { CompactBuilderFactory } from '@nodable/compact-builder';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const SHANGHAI_TZ = 'Asia/Shanghai';
const HISTORY_KEY = 'items';
const HISTORY_LIMIT = 200;
const HISTORY_RETENTION_MS = 3 * 24 * 60 * 60 * 1000;
const QWEATHER_API_HOST = 'mh7mdaq86q.re.qweatherapi.com';

const DEFAULT_RSS_SOURCES = [
    {
        sourceKey: 'picture of the day', feedUrl: 'https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=potd&feedformat=atom',
        crons: ['15 0 * * *']
    },
    {
        sourceKey: 'on this day', feedUrl: 'https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=onthisday&feedformat=atom',
        crons: ['15 0 * * *']
    },
    {
        sourceKey: 'do you know', feedUrl: 'https://zh.wikipedia.org/w/api.php?action=featuredfeed&feed=dyk&feedformat=atom',
        crons: ['15 0 * * *']
    },
    {
        sourceKey: 'sspai', feedUrl: 'https://sspai.com/feed',
        push: [], ignore: [],
        crons: ['0 0,4,8,12 * * *']
    },
    {
        sourceKey: 'ithome', feedUrl: 'https://www.ithome.com/rss/',
        push: ["苹果", "微软", "谷歌"], ignore: ['追觅', '小鹏', '奥迪', '快手', '抖音', '微博', '比亚迪', '零跑', '吉利', '领克', '鸿蒙智', '鼠标', '电影票房', '荣耀', '券', '智界', '问界', '尊界', '抖音', '车型', '补贴', '联名', '月卡', '年卡', '红包'],
        crons: ['0 0,4,8,12 * * *']
    }
];

const FEED_XML_PARSER = new XMLParser({
    skip: { attributes: false },
    attributes: { prefix: '' },
    nameFor: { cdata: '__cdata' },
    tags: {
        stopNodes: ['..summary', '..description', '..content']
    },
    OutputBuilder: new CompactBuilderFactory({
        tags:       { valueParsers: [] },
        attributes: { valueParsers: [] },
    }),
});

const UNWRAP_TAGS = new Set(['b', 'strong', 'em']);
const DROP_TAGS = new Set(['script', 'link', 'img']);
const DROP_ATTRIBUTES = new Set(['style', 'class', 'title']);
// const VOID_ELEMENTS = new Set(['br', 'hr', 'img', 'input', 'link', 'meta']);

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------
const b64toU8 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

async function aesGcmEncrypt(rawKeyB64, plaintext) {
    const key = await crypto.subtle.importKey('raw', b64toU8(rawKeyB64), 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
    return { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}

async function aesGcmDecrypt(rawKeyB64, ivArr, ctArr) {
    const key = await crypto.subtle.importKey('raw', b64toU8(rawKeyB64), 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(ivArr) }, key, new Uint8Array(ctArr).buffer);
    return new TextDecoder().decode(pt);
}

async function sha256hex(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacHex(secret, data, hash = 'SHA-256') {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: { name: hash } }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, data);
    return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// General utilities
// ---------------------------------------------------------------------------
const splitCsv = v => (v || '').split(',').map(s => s.trim()).filter(Boolean);

const toAbsoluteUrl = (url, base) => {
    try { return new URL(url, base || undefined).toString(); } catch { return url || ''; }
};

const safeEqual = (a, b) => {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    let out = 0;
    for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return out === 0;
};

const isOriginAllowed = (req, allowed) => {
    if (!allowed?.length) return true;
    const raw = req.headers.get('Origin') || req.headers.get('Referer') || '';
    try {
        const u = new URL(raw);
        return allowed.some(item => {
            if (raw === item || u.origin === item) return true;
            try { return new URL(item).hostname === u.hostname; }
            catch { return false; }
        });
    } catch { return false; }
};

// ---------------------------------------------------------------------------
// VAPID
// ---------------------------------------------------------------------------
let vapidInitialized = false;
function initializeVapid(env) {
    if (vapidInitialized) return;
    if (env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY) {
        setVapidDetails(env.VAPID_SUBJECT || 'mailto:nobody@example.com', env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY);
        vapidInitialized = true;
    }
}

// ---------------------------------------------------------------------------
// HTML sanitization (HTMLRewriter)
// ---------------------------------------------------------------------------
function sanitizeHref(href, baseUrl) {
    try {
        const u = new URL(href, baseUrl || undefined);
        if (u.protocol === 'http:' || u.protocol === 'https:') return u.toString();
    } catch { }
    return '';
}

// ---------------------------------------------------------------------------
// XML Parsing helpers
// ---------------------------------------------------------------------------
const asArray = v => v == null ? [] : Array.isArray(v) ? v : [v];
const xmlText = v => v == null ? '' : typeof v === 'string' ? v : Array.isArray(v) ? v.map(xmlText).filter(Boolean).join(' ') : String(v['#text'] || v.__cdata || '');
const xmlHtml = v => v == null ? '' : typeof v === 'string' ? v : Array.isArray(v) ? v.map(xmlHtml).filter(Boolean).join('') : String(v.__cdata || v['#text'] || '');

function resolveFeedLink(linkNode, baseUrl = '') {
    for (const link of asArray(linkNode)) {
        const href = typeof link === 'object' && link.href ? xmlText(link.href) : xmlText(link);
        const rel = typeof link === 'object' && link.rel ? xmlText(link.rel).trim().toLowerCase() : '';
        if (href.trim() && (!rel || rel === 'alternate')) return toAbsoluteUrl(href.trim(), baseUrl);
    }
    return '';
}

const parseFeedItemBase = (itemNode, feedBaseUrl) => {
    const link = resolveFeedLink(itemNode.link, feedBaseUrl);
    return {
        title: xmlText(itemNode.title).replace(/<[^>]+>/g, '').trim(),
        link,
        itemId: xmlText(itemNode.id || itemNode.guid).trim() || link,
        publishedAt: xmlText(itemNode.updated || itemNode.published || itemNode.pubDate).trim(),
        rawContent: xmlHtml(itemNode.summary || itemNode.content || itemNode.description)
    };
};

const ENTITIES = {
    nbsp: ' ', hellip: '…', mdash: '—', ndash: '–', lsquo: '‘', rsquo: '’',
    ldquo: '“', rdquo: '”', laquo: '«', raquo: '»', apos: "'", amp: '&', lt: '<', gt: '>', quot: '"'
};
const decodeXmlEntities = str => (str || '').replace(/&amp;#160;/g, '&#160;').replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, c) => {
    if (c[0] === '#') {
        const hex = c[1] === 'x' || c[1] === 'X';
        return String.fromCodePoint(parseInt(hex ? c.slice(2) : c.slice(1), hex ? 16 : 10));
    }
    return ENTITIES[c.toLowerCase()] || m;
});

class FeedItemParser {
    constructor(base, sourceKey) {
        this.base = base;
        this.sourceKey = sourceKey;
        this.rawContent = base.rawContent;
        this.sentences = 5;
        this.notiTitlePre = '';
        this.title = FeedItemParser.cleanText(base.title);
        this.cleanedContent = FeedItemParser.cleanText(this.rawContent);
    }

    static cleanText(str) {
        return decodeXmlEntities(str || '')
            .replace(/[\u0000-\u001f\u007f]+/g, ' ')
            .replace(/\s*['"`]*\s*UNIQ--[\w-]+-QINU\s*['"`]*\s*/g, ' ')
            .replace(/\s+/g, ' ').trim();
    }

    // HTMLRewriter callback entries
    element(el) {
        this.handleElement(el);
    }

    text(txt) {
        this.handleText(txt);
    }

    // Default implementations for sanitization/extraction
    handleElement(el) {
        const tag = el.tagName.toLowerCase();
        const baseUrl = this.base.link;

        if ((tag === 'img' || tag === 'media:content' || tag === 'media:thumbnail') && !this.imageUrl) {
            const src = el.getAttribute('src') || el.getAttribute('url');
            if (src) this.imageUrl = toAbsoluteUrl(src, baseUrl);
        }

        if (DROP_TAGS.has(tag) || (tag === 'span' && el.getAttribute('typeof') === 'mw:File')) {
            el.remove();
            if (tag !== 'img' && tag !== 'link') {
                this.dropDepth++;
                el.onEndTag(() => this.dropDepth--);
            }
            return;
        }

        if (UNWRAP_TAGS.has(tag)) return el.removeAndKeepContent();

        DROP_ATTRIBUTES.forEach(name => el.removeAttribute(name));

        if (tag === 'a') {
            const href = sanitizeHref(el.getAttribute('href'), baseUrl);
            if (href) el.setAttribute('href', href);
        }
    }

    handleText(txt) {
        if (this.dropDepth > 0) return;
        this.textParts.push(txt.text);
    }

    async parseHtml(html) {
        try {
            return (await new HTMLRewriter()
                .on('*', {
                    element: el => this.element(el),
                    text: txt => this.text(txt)
                })
                .transform(new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }))
                .text() || '').trim();
        } catch {
            return '';
        }
    }

    // Orchestrator: Runs the parser pipeline
    async parse() {
        const { content, text, imageUrl, title } = await this.extract(this.cleanedContent);
        const item = this.format(content, text, imageUrl, title ?? this.title);
        return this.postprocessItem(item);
    }

    // Hook 1: Run parser / sanitizer
    async extract(html) {
        this.dropDepth = 0;
        this.textParts = [];
        this.imageUrl = '';

        const content = await this.parseHtml(html);
        const text = FeedItemParser.cleanText(this.textParts.join(''));
        return { content, text, imageUrl: this.imageUrl, title: null };
    }

    // Hook 2: Assemble notification and body payload
    format(content, text, imageUrl, title) {
        let body = text;
        if (this.sentences > 0 && body) {
            const segmenter = new Intl.Segmenter(undefined, { granularity: 'sentence' });
            let count = 0;
            let truncated = '';
            for (const { segment } of segmenter.segment(body)) {
                truncated += segment;
                if (segment.trim() && ++count >= this.sentences) break;
            }
            body = truncated.trim();
        }
        if (!body) body = title;

        return {
            sourceKey: this.sourceKey,
            title,
            link: this.base.link,
            rawContent: this.rawContent,
            content,
            notiTitle: this.notiTitlePre ? `${this.notiTitlePre} ${title}` : title,
            notiBody: body,
            imageUrl,
            itemId: this.base.itemId,
            publishedAt: this.base.publishedAt
        };
    }

    // Hook 3: Final modification hook (e.g. set prefixes)
    postprocessItem(item) {
        return item;
    }
}

class IthomeFeedItemParser extends FeedItemParser {
    async parse() {
        return {
            sourceKey: this.sourceKey, title: this.title,
            link: this.base.link, rawContent: this.title, content: '',
            notiTitle: '[IThome]', notiBody: this.title, imageUrl: '',
            itemId: this.base.itemId, publishedAt: this.base.publishedAt
        };
    }
}

class PotdFeedItemParser extends FeedItemParser {
    constructor(base, sourceKey) {
        super(base, sourceKey);
        this.sentences = 1;
    }

    postprocessItem(item) {
        return {
            ...item,
            notiTitle: '[Potd]',
            content: ''
        };
    }
}

class OnThisDayFeedItemParser extends FeedItemParser {
    constructor(base, sourceKey) {
        super(base, sourceKey);
        this.sentences = 0;
    }

    handleElement(el) {
        const tag = el.tagName.toLowerCase();
        const baseUrl = this.base.link;

        if (tag === 'p') {
            if (!this.firstPDone) {
                this.insideP = true;
                el.onEndTag(() => {
                    this.insideP = false;
                    this.pTitle = this.pTitle.replace(/\s+/g, ' ').trim();
                    this.firstPDone = true;
                });
            }
        } else if (tag === 'img') {
            const src = el.getAttribute('src') || el.getAttribute('url');
            if (src && !this.imageUrl) {
                this.imageUrl = toAbsoluteUrl(src, baseUrl);
            }
        } else if (tag === 'li') {
            this.currentLiHtml = '';
            this.insideLi = true;
            el.onEndTag(() => {
                this.insideLi = false;
                const text = this.currentLiHtml.replace(/\s+/g, ' ').trim();
                if (/pictured|depicted/i.test(text) || !this.selectedLiText) {
                    this.selectedLiText = text;
                }
            });
        } else if (tag === 'a') {
            const href = el.getAttribute('href');
            const absHref = href ? toAbsoluteUrl(href, baseUrl) : '';
            if (href) {
                el.setAttribute('href', absHref);
            }
            if (this.insideLi) {
                this.currentLiHtml += `<a href="${absHref}">`;
                el.onEndTag(() => {
                    this.currentLiHtml += '</a>';
                });
            }
        }
    }

    handleText(txt) {
        if (this.insideLi) {
            this.currentLiHtml += txt.text;
        } else if (this.insideP && !this.firstPDone) {
            this.pTitle += txt.text;
        }
    }

    async extract(html) {
        this.pTitle = '';
        this.firstPDone = false;
        this.currentLiHtml = '';
        this.insideLi = false;
        this.insideP = false;
        this.selectedLiText = '';
        this.imageUrl = '';

        await this.parseHtml(html);

        const cleanedTitle = FeedItemParser.cleanText(this.pTitle) || this.title;
        const text = FeedItemParser.cleanText(this.selectedLiText.replace(/<[^>]+>/g, ''));
        return { content: this.selectedLiText, text, imageUrl: this.imageUrl, title: cleanedTitle };
    }

    postprocessItem(item) {
        return {
            ...item,
            notiTitle: `[Otd] ${item.title}`
        };
    }
}

class DoYouKnowFeedItemParser extends FeedItemParser {
    constructor(base, sourceKey) {
        super(base, sourceKey);
        this.sentences = 0;
        this.notiTitlePre = '[Dyk]';
    }

    handleElement(el) {
        const tag = el.tagName.toLowerCase();
        if (tag === 'li') {
            if (this.liCount >= 3) {
                el.remove();
                this.dropDepth++;
                el.onEndTag(() => this.dropDepth--);
                return;
            }
            el.onEndTag(() => {
                this.liCount++;
            });
        }
        super.handleElement(el);
    }

    async extract(html) {
        this.liCount = 0;
        return super.extract(html);
    }
}

class SspaiFeedItemParser extends FeedItemParser {
    constructor(base, sourceKey) {
        super(base, sourceKey);
        this.notiTitlePre = '[Pai]';
    }
}

const FEED_ITEM_PARSERS = {
    'ithome': IthomeFeedItemParser,
    'picture of the day': PotdFeedItemParser,
    'on this day': OnThisDayFeedItemParser,
    'do you know': DoYouKnowFeedItemParser,
    'sspai': SspaiFeedItemParser
};

async function parseFeedItem(itemNode, feedBaseUrl, source) {
    const sourceKey = (source?.sourceKey || '').toLowerCase();
    const base = parseFeedItemBase(itemNode, feedBaseUrl);
    const ParserClass = FEED_ITEM_PARSERS[sourceKey] || FeedItemParser;
    return new ParserClass(base, sourceKey).parse();
}

async function parseFeedItems(feedText, source = null) {
    const parsed = FEED_XML_PARSER.parse(feedText);
    const root = parsed.feed || parsed.rss?.channel;
    if (!root) return [];

    const baseUrl = resolveFeedLink(root.link || root.atomLink);
    const items = (await Promise.all(asArray(root.entry || root.item || []).map(n => parseFeedItem(n, baseUrl, source))));
    return items.sort((a, b) => Date.parse(a.publishedAt || 0) - Date.parse(b.publishedAt || 0));
}

const buildNotificationPayload = (item) => {
    return {
        web_push: 8030,
        notification: {
            title: item.notiTitle,
            body: item.notiBody || '',
            silent: false,
            app_badge: '1',
            ...(item.link ? { navigate: item.link } : {})
        }
    };
};

const Store = {
    deriveKey: item => item.itemId || item.link || `${item.title}::${item.publishedAt || ''}`,
    getPointer: (env, sourceKey) => env.SUBS.get(`pointer:${sourceKey}`),
    setPointer: (env, sourceKey, key) => env.SUBS.put(`pointer:${sourceKey}`, key),
    getHistory: async env => JSON.parse(await env.SUBS.get(HISTORY_KEY) || '[]'),
    saveHistory: (env, history) => env.SUBS.put(HISTORY_KEY, JSON.stringify(history))
};

const getUnseenItems = (items, lastKey = '') => {
    const list = asArray(items).filter(Boolean);
    const idx = lastKey ? list.findIndex(it => Store.deriveKey(it) === lastKey) : -1;
    return idx < 0 ? list : list.slice(idx + 1);
};

async function processSourceItem(env, source, item, opts = {}) {
    const { updateLastSeen = true } = opts;
    const key = Store.deriveKey(item);
    if (!key) return { skipped: true, reason: 'missing_key', sourceKey: source.sourceKey };

    const lastKey = await Store.getPointer(env, source.sourceKey);
    if (lastKey === key) return { skipped: true, reason: 'duplicate', sourceKey: source.sourceKey, itemKey: key };

    const cfg = DEFAULT_RSS_SOURCES.find(f => f.sourceKey === source.sourceKey);
    let cachedFilterText = null;
    const getFilterText = () => cachedFilterText ??= [item.title, item.notiBody].filter(Boolean).join(' ').toLowerCase();

    // Step 1: Check ignore keywords — skip entirely
    if (cfg?.ignore?.length && cfg.ignore.some(kw => getFilterText().includes(kw.toLowerCase()))) {
        if (updateLastSeen) await Store.setPointer(env, source.sourceKey, key);
        return { skipped: true, reason: 'ignored', sourceKey: source.sourceKey, itemKey: key };
    }

    // Step 2: Check push keywords (whitelist)
    let shouldPush = true;
    if (cfg?.push?.length && !cfg.push.some(kw => getFilterText().includes(kw.toLowerCase()))) {
        shouldPush = false;
    }

    // Step 3: Build history item and save
    const notiBody = item.notiBody || item.title || '';
    const historyItem = {
        id: `${source.sourceKey}:${key}`,
        sourceKey: source.sourceKey,
        title: item.title || '',
        content: item.content || '',
        link: item.link || '',
        imageUrl: item.imageUrl || '',
        publishedAt: item.publishedAt || '',
        description: notiBody,
        notiTitle: item.notiTitle || '',
        notiBody: notiBody,
        createdAt: new Date().toISOString()
    };

    const history = await Store.getHistory(env);
    const nextHistory = [historyItem, ...history.filter(it => it.id !== historyItem.id && (Date.now() - Date.parse(it.createdAt)) <= HISTORY_RETENTION_MS)].slice(0, HISTORY_LIMIT);
    await Store.saveHistory(env, nextHistory);

    // Step 4: Send push notification
    const result = shouldPush
        ? await sendToAllSubscriptions(env, buildNotificationPayload(historyItem))
        : { sent: 0, failed: 0 };
    if (updateLastSeen) await Store.setPointer(env, source.sourceKey, key);
    return { skipped: false, sourceKey: source.sourceKey, itemKey: key, ...result };
}

async function processFeedItems(env, source, items, opts = {}) {
    const lastKey = opts.lastItemKey || await Store.getPointer(env, source.sourceKey) || '';
    const unseen = getUnseenItems(items, lastKey);
    const results = { sourceKey: source.sourceKey, total: unseen.length, processed: 0, sent: 0, failed: 0, errors: [] };

    for (const item of unseen) {
        const r = await processSourceItem(env, source, item, opts);
        if (r.skipped) { continue; }
        results.processed++;
        results.sent += r.sent || 0;
        results.failed += r.failed || 0;
        if (r.errors?.length) results.errors.push(...r.errors);
        if (r.failed > 0) break;
    }
    return results;
}

async function processFetchedFeedText(env, source, feedText, opts = {}) {
    const items = await parseFeedItems(feedText, source);
    if (!items.length) return { reason: 'no_items', sourceKey: source.sourceKey };
    return processFeedItems(env, source, items, opts);
}

async function fetchFeedPreview(feedUrl) {
    const res = await fetch(feedUrl, {
        headers: { 'User-Agent': 'Attention-Worker/1.0', Accept: 'application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.1' }
    });
    return { status: res.status, contentType: res.headers.get('content-type') || '', text: await res.text() };
}

// ---------------------------------------------------------------------------
// QWeather
// ---------------------------------------------------------------------------
const buildQWeatherSource = env => env.QWEATHER_LOCATION && (env.QWEATHER_PRIVATE_KEY || env.qweather_key) ? { sourceKey: 'Weather', location: env.QWEATHER_LOCATION } : null;

async function fetchQWeatherHourlyForecast(env, location) {
    const res = await fetch(`https://${QWEATHER_API_HOST}/v7/weather/24h?location=${encodeURIComponent(location)}`, {
        headers: { Authorization: await buildQWeatherAuthorizationHeader(env) }
    });
    const data = res.ok && await res.json();
    if (!data || data.code !== '200' || !Array.isArray(data.hourly)) throw new Error(`QWeather failed: ${res.status}/${data?.code}`);
    return data;
}

function buildRainAlertItem(forecast) {
    const rainy = forecast.hourly.slice(0, 6).find(h => Number(h.precip || 0) > 0 || (Number(h.pop || 0) > 0 && /(雨|雷阵雨|阵雨|rain|shower|drizzle|thunder|storm)/i.test(h.text)));
    if (!rainy) return null;

    let time = rainy.fxTime;
    try {
        time = new Intl.DateTimeFormat('en-GB', { timeZone: SHANGHAI_TZ, hour: '2-digit', minute: '2-digit', hour12: false, month: 'numeric', day: 'numeric' }).format(new Date(time));
    } catch { }

    const details = [rainy.text, rainy.pop && `PoP ${rainy.pop}%`, Number(rainy.precip || 0) > 0 && `Precip ${rainy.precip} mm`].filter(Boolean).join(' · ');
    const summary = `Weather expected by ${time}. ${details}`;

    return {
        title: 'Weather', description: summary, content: `<p>${summary}</p>`, notiBody: summary,
        link: '', imageUrl: '', itemId: rainy.fxTime, publishedAt: rainy.fxTime
    };
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
    const { keys } = await env.SUBS.list();
    const out = [];
    for (const { name } of keys) {
        if (name === 'items' || name.startsWith('pointer:')) continue;
        try {
            const raw = await env.SUBS.get(name);
            if (!raw) continue;
            const { iv, ct } = JSON.parse(raw);
            const { sub } = JSON.parse(await aesGcmDecrypt(env.SUBS_ENC_KEY, iv, ct));
            if (sub?.endpoint) out.push(sub);
        } catch { }
    }
    return out;
}

async function sendToAllSubscriptions(env, payload) {
    const subs = await listSubscriptions(env);
    const results = { total: subs.length, sent: 0, failed: 0, errors: [] };
    console.log(`[Push] subs=${subs.length}, payload=${JSON.stringify(payload).slice(0, 300)}`);
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

        if (request.method === 'GET' && url.pathname === '/config') {
            return json({ vapidPublicKey: env.VAPID_PUBLIC_KEY || '' });
        }

        if (request.method === 'GET' && url.pathname === '/history') {
            const now = Date.now();
            let items = (await Store.getHistory(env)).filter(it => (now - Date.parse(it.createdAt)) <= HISTORY_RETENTION_MS);
            
            const since = url.searchParams.get('since');
            if (since) {
                const sinceTime = Date.parse(since);
                if (Number.isFinite(sinceTime)) {
                    items = items.filter(it => Date.parse(it.createdAt) > sinceTime);
                }
            }
            return json({ ok: true, items });
        }

        if (request.method === 'POST' && url.pathname === '/subscribe') {
            if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
            const sub = await request.json();
            if (!sub?.endpoint) return new Response('Bad Request', { status: 400 });

            const key = await sha256hex(sub.endpoint);
            const { iv, ct } = await aesGcmEncrypt(env.SUBS_ENC_KEY, JSON.stringify({ sub, created: Date.now() }));
            await env.SUBS.put(key, JSON.stringify({ iv, ct }));
            return json({ status: 'ok' });
        }

        if (request.method === 'POST' && url.pathname === '/unsubscribe') {
            if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
            const body = await request.json();
            if (!body?.endpoint) return new Response('Bad Request', { status: 400 });
            const key = await sha256hex(body.endpoint);
            await env.SUBS.delete(key);
            return json({ status: 'deleted' });
        }


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
                if (env.WEBSUB_SECRET && !(await verifyWebhookSignature(request, rawBody, env.WEBSUB_SECRET))) return new Response('Unauthorized', { status: 401 });
                const fallbackUrl = url.searchParams.get('hub.topic') || '';
                ctx?.waitUntil?.(processFetchedFeedText(env, { sourceKey: fallbackUrl ? `websub:${fallbackUrl}` : 'websub:unknown' }, new TextDecoder().decode(rawBody), { updateLastSeen: true }));
                return new Response(null, { status: 204 });
            }
            return new Response('Method Not Allowed', { status: 405 });
        }

        if (request.method === 'POST' && url.pathname === '/websub/subscribe') {
            if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
            const body = await request.json().catch(() => ({}));
            const {
                hub = env.WEBSUB_HUB_URL || '',
                topic = env.WEBSUB_TOPIC || '',
                callback = env.WEBSUB_CALLBACK_URL || `${url.origin}/websub`,
                secret = env.WEBSUB_SECRET || '',
                lease_seconds: lease = env.WEBSUB_LEASE_SECONDS || '864000'
            } = body;
            if (!hub || !topic || !callback) return new Response('Missing hub, topic, or callback URL', { status: 400 });

            const res = await fetch(hub, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ 'hub.mode': 'subscribe', 'hub.topic': topic, 'hub.callback': callback, 'hub.secret': secret, 'hub.lease_seconds': lease })
            });
            return json({ ok: res.ok, status: res.status, body: await res.text().catch(() => '') }, res.status);
        }

        if (request.method === 'POST' && url.pathname === '/websub/unsubscribe') {
            if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
            const body = await request.json().catch(() => ({}));
            const {
                hub = env.WEBSUB_HUB_URL || '',
                topic = env.WEBSUB_TOPIC || '',
                callback = env.WEBSUB_CALLBACK_URL || `${url.origin}/websub`
            } = body;
            if (!hub || !topic || !callback) return new Response('Missing hub, topic, or callback URL', { status: 400 });

            const res = await fetch(hub, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ 'hub.mode': 'unsubscribe', 'hub.topic': topic, 'hub.callback': callback })
            });
            return json({ ok: res.ok, status: res.status, body: await res.text().catch(() => '') }, res.status);
        }

        if (request.method === 'POST' && url.pathname === '/webhook') {
            if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
            const rawBody = await request.arrayBuffer();
            if (env.WEBHOOK_SECRET && !(await verifyWebhookSignature(request, rawBody, env.WEBHOOK_SECRET))) return new Response('Unauthorized', { status: 401 });
            if (!(request.headers.get('content-type') || '').includes('application/json')) return new Response(null, { status: 204 });

            const body = JSON.parse(new TextDecoder().decode(rawBody));
            if (!body?.title) return new Response(null, { status: 204 });

            ctx?.waitUntil?.(processSourceItem(env, { sourceKey: body.sourceKey || 'webhook:default' }, {
                title: body.title, description: body.body || '',
                content: body.bodyHtml || '', link: body.link || '', imageUrl: body.imageUrl || '',
                notiBody: body.body || '',
                itemId: body.itemKey || body.id || body.link || '', publishedAt: body.publishedAt || new Date().toISOString()
            }, { updateLastSeen: true }));
            return new Response(null, { status: 204 });
        }

        if (request.method === 'POST' && url.pathname === '/rss/send') {
            if ((request.headers.get('x-api-key') || '') !== env.SEND_API_KEY) return new Response('Unauthorized', { status: 401 });
            const body = await request.json().catch(() => ({}));
            let feedUrl = body.url || '';
            if (body.sourceKey) {
                const cfg = DEFAULT_RSS_SOURCES.find(f => f.sourceKey.toLowerCase() === body.sourceKey.toLowerCase());
                if (cfg) feedUrl = cfg.feedUrl;
            }
            if (!feedUrl) feedUrl = env.POLL_URL || '';
            if (!feedUrl) return new Response('Missing feed URL or sourceKey', { status: 400 });

            const preview = await fetchFeedPreview(feedUrl);
            if (preview.status < 200 || preview.status >= 300) return json({ ok: false, status: preview.status, error: 'Feed fetch failed' }, 502);

            const cfg = DEFAULT_RSS_SOURCES.find(f => f.feedUrl === feedUrl);
            const result = await processFetchedFeedText(env, { sourceKey: cfg?.sourceKey || feedUrl }, preview.text, { updateLastSeen: true });
            return json({ ok: result.failed === 0, ...result }, result.failed === 0 ? 200 : 207);
        }

        return env.ASSETS.fetch(request);
    },

    async scheduled(controller, env, ctx) {
        initializeVapid(env);
        if (controller.cron === '0 */3 * * *') {
            ctx?.waitUntil?.(processQWeatherRainAlert(env).catch(e => console.error('Weather check failed', e)));
            return;
        }
        ctx?.waitUntil?.((async () => {
            for (const cfg of DEFAULT_RSS_SOURCES) {
                if (!cfg.crons?.includes(controller.cron)) continue;
                try {
                    const prev = await fetchFeedPreview(cfg.feedUrl);
                    if (prev.status >= 200 && prev.status < 300) {
                        await processFetchedFeedText(env, { sourceKey: cfg.sourceKey }, prev.text);
                    }
                } catch (e) {
                    console.error(`Scheduled failed: ${cfg.sourceKey}`, e);
                }
            }
        })());
    }
};
