import { setVapidDetails, sendNotification } from './pwanotify.js';
import { buildQWeatherAuthorizationHeader } from './qweather-jwt.js';
import { XMLParser } from 'fast-xml-parser';

const SHANGHAI_TIME_ZONE = 'Asia/Shanghai';
const HISTORY_KEY = 'history:items';
const HISTORY_LIMIT = 50;
const HISTORY_RETENTION_MS = 3 * 24 * 60 * 60 * 1000;
const QWEATHER_API_HOST = 'mh7mdaq86q.re.qweatherapi.com';
const DEFAULT_RSS_SOURCES = [
  {
    sourceKey: 'WikiPOTD',
    feedUrl: 'https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=potd&feedformat=atom'
  },
  {
    sourceKey: 'WikiOnThisDay',
    feedUrl: 'https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=onthisday&feedformat=atom',
    imageWidth: 250
  },
  {
    sourceKey: 'WikiDYK',
    feedUrl: 'https://zh.wikipedia.org/w/api.php?action=featuredfeed&feed=dyk&feedformat=atom',
    lang: 'zh'
  }
];
const FEED_XML_PARSER = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  trimValues: false,
  parseTagValue: false,
  parseAttributeValue: false,
  processEntities: false,
  cdataPropName: '__cdata',
  stopNodes: ['*.summary', '*.content', '*.description']
});
const ALLOWED_SUMMARY_TAGS = new Set(['p', 'a', 'ul', 'ol', 'li', 'b', 'strong', 'i', 'em', 'abbr', 'small', 'sup', 'sub', 'br']);
const DROP_SUMMARY_TAGS = new Set(['script', 'style', 'link', 'img']);

function base64ToUint8Array(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function aesGcmEncrypt(rawKeyBase64, plaintextStr) {
  const keyBytes = base64ToUint8Array(rawKeyBase64);
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintextStr));
  return { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}

async function aesGcmDecrypt(rawKeyBase64, ivArr, ctArr) {
  const keyBytes = base64ToUint8Array(rawKeyBase64);
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const iv = new Uint8Array(ivArr);
  const ct = new Uint8Array(ctArr).buffer;
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(ptBuf);
}

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  const arr = new Uint8Array(buf);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function splitCsv(value) {
  return (value || '').split(',').map(s => s.trim()).filter(Boolean);
}

function getRequestOrigin(request) {
  return request.headers.get('Origin') || request.headers.get('Referer') || '';
}

function isOriginAllowed(request, allowedList) {
  if (!allowedList || allowedList.length === 0) return true;
  const origin = getRequestOrigin(request);
  if (!origin) return false;
  return allowedList.some(item => origin.startsWith(item));
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

function formEncode(params) {
  return Object.entries(params)
    .filter(([, value]) => value !== undefined && value !== null && String(value).length > 0)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
    .join('&');
}

function initializeVapid(env) {
  if (env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY) {
    setVapidDetails(
      env.VAPID_SUBJECT || 'mailto:nobody@example.com',
      env.VAPID_PUBLIC_KEY,
      env.VAPID_PRIVATE_KEY
    );
  }
}

async function hmacHex(secret, data, hash = 'SHA-256') {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: { name: hash } },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

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

async function fetchFeedPreview(feedUrl) {
  const res = await fetch(feedUrl, {
    headers: {
      'User-Agent': 'Attention-Worker/1.0',
      'Accept': 'application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.1'
    }
  });
  const text = await res.text();
  return { status: res.status, contentType: res.headers.get('content-type') || '', text };
}

function normalizeApiHost(host) {
  if (!host) return '';
  return /^https?:\/\//i.test(host) ? host.replace(/\/+$/g, '') : `https://${host.replace(/\/+$/g, '')}`;
}

function formatHourlyForecastTime(value) {
  try {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: SHANGHAI_TIME_ZONE,
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
      month: 'numeric',
      day: 'numeric'
    }).format(new Date(value));
  } catch {
    return value || '';
  }
}

function isRainText(text) {
  return /(rain|shower|drizzle|thunder|storm|雨|雷阵雨|阵雨)/i.test(String(text || ''));
}

function buildQWeatherSource(env) {
  const location = env.QWEATHER_LOCATION || '';
  const privateKey = env.QWEATHER_PRIVATE_KEY || env.qweather_key || '';
  if (!location || !privateKey) return null;
  return {
    sourceKey: 'Weather',
    sourceType: 'weather',
    location
  };
}

async function fetchQWeatherHourlyForecast(env, location) {
  const apiHost = normalizeApiHost(QWEATHER_API_HOST);
  if (!apiHost) throw new Error('Missing QWEATHER_API_HOST');
  const url = new URL('/v7/weather/24h', apiHost);
  url.searchParams.set('location', location);

  const res = await fetch(url.toString(), {
    headers: {
      Authorization: await buildQWeatherAuthorizationHeader(env),
      Accept: 'application/json'
    }
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`QWeather request failed: ${res.status}`);
  if (!data || data.code !== '200' || !Array.isArray(data.hourly)) {
    throw new Error(`QWeather response invalid: ${data && data.code ? data.code : 'unknown'}`);
  }
  return data;
}

function buildRainAlertItem(forecast, sourceKey) {
  const hourly = Array.isArray(forecast.hourly) ? forecast.hourly.slice(0, 6) : [];
  const rainyHour = hourly.find((hour) => {
    const precip = Number(hour.precip || 0);
    const pop = Number(hour.pop || 0);
    return precip > 0 || (pop > 0 && isRainText(hour.text));
  });
  if (!rainyHour) return null;

  const at = formatHourlyForecastTime(rainyHour.fxTime);
  const details = [
    rainyHour.text || '',
    rainyHour.pop ? `PoP ${rainyHour.pop}%` : '',
    Number(rainyHour.precip || 0) > 0 ? `Precip ${rainyHour.precip} mm` : ''
  ].filter(Boolean).join(' · ');
  const summaryText = `${sourceKey} expected by ${at}. ${details}`.trim();

  return {
    title: sourceKey,
    description: summaryText,
    summaryText,
    summaryHtml: `<p>${escapeHtml(summaryText)}</p>`,
    link: '',
    imageUrl: '',
    itemId: rainyHour.fxTime,
    publishedAt: rainyHour.fxTime
  };
}

function escapeHtml(str) {
  return (str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function toAbsoluteUrl(url, baseUrl = '') {
  if (!url) return '';
  if (url.startsWith('//')) return `https:${url}`;
  try {
    return baseUrl ? new URL(url, baseUrl).toString() : new URL(url).toString();
  } catch {
    return url;
  }
}

function decodeXmlEntities(str) {
  return (str || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_, code) => {
      try {
        return String.fromCodePoint(Number(code));
      } catch {
        return _;
      }
    })
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => {
      try {
        return String.fromCodePoint(parseInt(code, 16));
      } catch {
        return _;
      }
    })
    .trim();
}

function normalizeMarkupNoise(str) {
  return (str || '')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<link[\s\S]*?\/?>/gi, ' ')
    .replace(/[\u0000-\u001f\u007f]*\s*['"`]*\s*UNIQ--[\w-]+-QINU\s*['"`]*\s*[\u0000-\u001f\u007f]*/g, ' ')
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function stripTags(str) {
  return normalizeMarkupNoise(
    decodeXmlEntities((str || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' '))
  ).trim();
}

function truncateToSentence(text, maxLength = 180) {
  const normalized = (text || '').replace(/\s+/g, ' ').trim();
  if (!normalized || normalized.length <= maxLength) return normalized;
  const slice = normalized.slice(0, maxLength);
  const lastSentenceEnd = Math.max(
    slice.lastIndexOf('. '),
    slice.lastIndexOf('! '),
    slice.lastIndexOf('? '),
    slice.lastIndexOf('。'),
    slice.lastIndexOf('！'),
    slice.lastIndexOf('？')
  );
  if (lastSentenceEnd >= 20) {
    return `${slice.slice(0, lastSentenceEnd + 1).trim()}...`;
  }
  return `${slice.trim()}...`;
}

function cleanHistoryBodyText(text) {
  const cleaned = normalizeMarkupNoise((text || '').replace(/\s+/g, ' ')).trim();
  if (!cleaned) return '';
  if (/[.!?。！？…]$/.test(cleaned)) return cleaned;
  return `${cleaned}...`;
}

function isSentenceTerminator(text, index) {
  const ch = text[index];
  if (!/[.!?。！？]/.test(ch)) return false;

  const prev = index > 0 ? text[index - 1] : '';
  const next = index + 1 < text.length ? text[index + 1] : '';

  if (ch === '.' && /\d/.test(prev) && /\d/.test(next)) {
    return false;
  }

  return true;
}

function truncateSanitizedHtml(html, maxSentences) {
  const source = html || '';
  let output = '';
  let sentenceCount = 0;
  let insideTag = false;
  const stack = [];

  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    output += ch;

    if (insideTag) {
      if (ch === '>') {
        insideTag = false;
        const tagText = output.slice(output.lastIndexOf('<') + 1, output.length - 1).trim();
        if (!tagText || tagText.startsWith('!') || tagText.startsWith('?')) continue;
        if (tagText.startsWith('/')) {
          const closingName = tagText.slice(1).split(/\s+/)[0].toLowerCase();
          const idx = stack.lastIndexOf(closingName);
          if (idx >= 0) stack.splice(idx, 1);
          continue;
        }
        const selfClosing = tagText.endsWith('/');
        const openingName = tagText.replace(/\/$/, '').split(/\s+/)[0].toLowerCase();
        if (!selfClosing && openingName !== 'br') stack.push(openingName);
      }
      continue;
    }

    if (ch === '<') {
      insideTag = true;
      continue;
    }

    if (!isSentenceTerminator(source, i)) continue;
    sentenceCount += 1;
    if (sentenceCount < maxSentences) continue;

    while (stack.length) {
      output += `</${stack.pop()}>`;
    }
    return output.trim();
  }

  return source.trim();
}

function asArray(value) {
  if (value == null) return [];
  return Array.isArray(value) ? value : [value];
}

function isRecord(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function nodeText(value) {
  if (value == null) return '';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return decodeXmlEntities(String(value)).trim();
  }
  if (Array.isArray(value)) {
    return value.map((item) => nodeText(item)).filter(Boolean).join(' ').trim();
  }
  if (isRecord(value)) {
    return decodeXmlEntities(`${value['#text'] || ''}${value.__cdata || ''}`).trim();
  }
  return '';
}

function nodeHtml(value) {
  if (value == null) return '';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return decodeXmlEntities(String(value)).trim();
  }
  if (Array.isArray(value)) {
    return value.map((item) => nodeHtml(item)).filter(Boolean).join('').trim();
  }
  if (isRecord(value)) {
    if (typeof value.__cdata === 'string') {
      return decodeXmlEntities(value.__cdata).trim();
    }
    if (typeof value['#text'] === 'string') {
      return decodeXmlEntities(value['#text']).trim();
    }
  }
  return '';
}

function firstMatch(text, patterns) {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match && match[1]) return match[1].trim();
  }
  return '';
}

function extractHtmlAttribute(tag, name) {
  if (!tag || !name) return '';
  const match = tag.match(new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, 'i'));
  return match ? decodeXmlEntities(match[1]) : '';
}

function extractPrimaryImage(summaryHtml, baseUrl = '') {
  const imageTag = summaryHtml.match(/<img\b[^>]*>/i)?.[0] || '';
  const imageSrc = extractHtmlAttribute(imageTag, 'src');
  if (imageSrc) {
    return {
      imageUrl: toAbsoluteUrl(imageSrc, baseUrl),
      imageAlt: extractHtmlAttribute(imageTag, 'alt')
    };
  }

  return {
    imageUrl: toAbsoluteUrl(firstMatch(summaryHtml, [
      /<media:content[^>]*url=["']([^"']+)["'][^>]*\/?>/i,
      /<media:thumbnail[^>]*url=["']([^"']+)["'][^>]*\/?>/i
    ]), baseUrl),
    imageAlt: ''
  };
}

function extractFeedLink(linkNode, baseUrl = '') {
  for (const link of asArray(linkNode)) {
    if (isRecord(link)) {
      const href = nodeText(link.href);
      const rel = nodeText(link.rel).toLowerCase();
      if (href && (!rel || rel === 'alternate')) return toAbsoluteUrl(href, baseUrl);
    } else {
      const href = nodeText(link);
      if (href) return toAbsoluteUrl(href, baseUrl);
    }
  }
  return '';
}

async function parseFeedItemNode(itemNode, feedMeta) {
  const { baseUrl = '' } = feedMeta || {};
  const title = stripTags(nodeText(itemNode.title));
  const link = extractFeedLink(itemNode.link, baseUrl) || toAbsoluteUrl(nodeText(itemNode.link), baseUrl);
  const itemId = nodeText(itemNode.id || itemNode.guid) || link;
  const publishedAt = nodeText(itemNode.updated || itemNode.published || itemNode.pubDate);
  const rawSummaryHtml = nodeHtml(itemNode.summary || itemNode.content || itemNode.description);
  const description = truncateToSentence(stripTags(rawSummaryHtml), 180);
  const { imageUrl, imageAlt } = extractPrimaryImage(rawSummaryHtml, baseUrl || link);
  const summaryHtml = await sanitizeSummaryHtml(rawSummaryHtml, description, baseUrl || link);

  return { title, link, description, summaryText: description, summaryHtml, imageUrl, imageAlt, itemId, publishedAt };
}

async function parseLatestFeedItem(feedText) {
  const parsed = FEED_XML_PARSER.parse(feedText);
  const feedRoot = parsed.feed || parsed.rss?.channel || null;
  if (!feedRoot) return null;

  const feedMeta = {
    baseUrl: extractFeedLink(feedRoot.link || feedRoot.atomLink, '')
  };
  const rawItems = feedRoot.entry || feedRoot.item || [];
  const parsedItems = (await Promise.all(asArray(rawItems).map((itemNode) => parseFeedItemNode(itemNode, feedMeta))))
    .filter((item) => item && item.title);

  if (parsedItems.length === 0) return null;

  parsedItems.sort((a, b) => {
    const aTime = Date.parse(a.publishedAt || 0);
    const bTime = Date.parse(b.publishedAt || 0);
    return aTime - bTime;
  });
  return parsedItems.at(-1);
}

function sanitizeSummaryHref(href, baseUrl = '') {
  const resolved = toAbsoluteUrl(href || '', baseUrl);
  try {
    const url = new URL(resolved);
    if (url.protocol === 'http:' || url.protocol === 'https:') return url.toString();
  } catch {
  }
  return '';
}

class SummaryElementSanitizer {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
  }

  element(element) {
    const rawTag = typeof element.tagName === 'string' ? element.tagName : '';
    if (!rawTag) return;
    const tag = rawTag.toLowerCase();
    if (tag === 'summary-root') return;
    if (DROP_SUMMARY_TAGS.has(tag)) {
      element.remove();
      return;
    }
    if (!ALLOWED_SUMMARY_TAGS.has(tag)) {
      element.removeAndKeepContent();
      return;
    }

    for (const attr of Array.from(element.attributes || [])) {
      const rawName = typeof attr?.name === 'string' ? attr.name : '';
      if (!rawName) continue;
      const name = rawName.toLowerCase();
      if (tag === 'a' && name === 'href') continue;
      element.removeAttribute(rawName);
    }

    if (tag === 'a') {
      const href = sanitizeSummaryHref(element.getAttribute('href') || '', this.baseUrl);
      if (href) {
        element.setAttribute('href', href);
      } else {
        element.removeAndKeepContent();
      }
    }
  }
}

class SummaryDocumentSanitizer {
  comments(comment) {
    comment.remove();
  }
}

async function sanitizeSummaryHtml(summaryHtml, summaryText, baseUrl = '') {
  if (!summaryHtml) return summaryText ? `<p>${escapeHtml(summaryText)}</p>` : '';
  const wrapped = `<summary-root>${normalizeMarkupNoise(summaryHtml)}</summary-root>`;
  const rewritten = await new HTMLRewriter()
    .on('*', new SummaryElementSanitizer(baseUrl))
    .onDocument(new SummaryDocumentSanitizer())
    .transform(new Response(wrapped, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    }))
    .text();
  const sanitized = truncateSanitizedHtml(rewritten
    .replace(/^<summary-root>/i, '')
    .replace(/<\/summary-root>$/i, '')
    .trim(), 3);
  return sanitized || (summaryText ? `<p>${escapeHtml(summaryText)}</p>` : '');
}

function buildNotificationPayload(item) {
  const notification = {
    title: item.title,
    body: item.summaryText || item.description || 'New item',
    silent: false,
    app_badge: '1'
  };
  if (item.link) notification.navigate = item.link;
  return {
    web_push: 8030,
    notification
  };
}

function getSourceCurrentKey(sourceKey) {
  return `source:current:${sourceKey}`;
}

function getSourceLastItemKey(sourceKey) {
  return `source:last:${sourceKey}`;
}

function deriveItemKey(item) {
  return item.itemId || item.link || `${item.title}::${item.publishedAt || item.updatedAt || ''}`;
}

function resizeWikipediaThumb(url, width) {
  if (!url || !width) return url || '';
  return url.replace(/\/thumb\/([^/]+\/[^/]+)\/\d+px-([^/?#]+)([?#].*)?$/i, `/thumb/$1/${width}px-$2$3`);
}

function normalizeScheduledFeedItem(feedConfig, item) {
  if (!item) return item;
  if (!feedConfig?.imageWidth) return item;
  return {
    ...item,
    imageUrl: resizeWikipediaThumb(item.imageUrl, feedConfig.imageWidth)
  };
}

function getScheduledFeedConfig(feedUrl) {
  return DEFAULT_RSS_SOURCES.find((feed) => feed.feedUrl === feedUrl) || null;
}

async function getStateJson(env, key) {
  const raw = await env.SUBS.get(key);
  if (!raw) return null;
  return JSON.parse(raw);
}

async function putStateJson(env, key, value) {
  await env.SUBS.put(key, JSON.stringify(value));
}

async function appendHistoryItem(env, historyItem) {
  const now = Date.now();
  const history = (await getStateJson(env, HISTORY_KEY) || []).filter((item) => {
    const createdAt = item && item.createdAt ? Date.parse(item.createdAt) : 0;
    return createdAt && (now - createdAt) <= HISTORY_RETENTION_MS;
  });
  const next = [historyItem, ...history.filter(item => item.id !== historyItem.id)]
    .sort((a, b) => Date.parse(b.createdAt || 0) - Date.parse(a.createdAt || 0))
    .slice(0, HISTORY_LIMIT);
  await putStateJson(env, HISTORY_KEY, next);
  return next;
}

async function refreshScheduledRssFeedState(env, feedConfig) {
  const { feedUrl } = feedConfig;
  const preview = await fetchFeedPreview(feedUrl);
  if (preview.status < 200 || preview.status >= 300) {
    throw new Error(`Scheduled feed fetch failed: ${preview.status}`);
  }

  const item = normalizeScheduledFeedItem(feedConfig, await parseLatestFeedItem(preview.text));
  if (!item) throw new Error('Unable to parse scheduled feed');
  item.date = (item.publishedAt || '').slice(0, 10);

  const sourceKey = feedConfig.sourceKey;
  const current = await getStateJson(env, getSourceCurrentKey(sourceKey));
  const changed = !current ||
    current.date !== item.date ||
    current.title !== item.title ||
    current.link !== item.link ||
    current.summaryText !== item.summaryText ||
    current.imageUrl !== item.imageUrl ||
    current.imageAlt !== item.imageAlt;

  if (changed) {
    await putStateJson(env, getSourceCurrentKey(sourceKey), item);
  }

  return { item, changed };
}

async function processSourceItem(env, source, item, options = {}) {
  const { cacheCurrent = true } = options;
  const itemKey = deriveItemKey(item);
  if (!itemKey) return { skipped: true, reason: 'missing_item_key', sourceKey: source.sourceKey };

  if (cacheCurrent) {
    await putStateJson(env, getSourceCurrentKey(source.sourceKey), item);
  }

  const lastItemKey = await env.SUBS.get(getSourceLastItemKey(source.sourceKey));
  if (lastItemKey === itemKey) {
    return { skipped: true, reason: 'duplicate', sourceKey: source.sourceKey, itemKey };
  }

  const result = await sendToAllSubscriptions(env, buildNotificationPayload(item));
  await env.SUBS.put(getSourceLastItemKey(source.sourceKey), itemKey);
  const historyItem = {
    id: `${source.sourceKey}:${itemKey}`,
    sourceKey: source.sourceKey,
    lang: source.lang || '',
    title: item.title || '',
    summaryHtml: item.summaryHtml || '',
    link: item.link || '',
    imageUrl: item.imageUrl || '',
    imageAlt: item.imageAlt || '',
    publishedAt: item.publishedAt || item.updatedAt || '',
    createdAt: new Date().toISOString()
  };
  await appendHistoryItem(env, historyItem);
  return {
    skipped: false,
    sourceKey: source.sourceKey,
    item,
    itemKey,
    ...result
  };
}

async function processQWeatherRainAlert(env) {
  const source = buildQWeatherSource(env);
  if (!source) return { skipped: true, reason: 'missing_qweather_location' };
  const forecast = await fetchQWeatherHourlyForecast(env, source.location);
  const item = buildRainAlertItem(forecast, source.sourceKey);
  if (!item) return { skipped: true, reason: 'no_rain_within_6h', sourceKey: source.sourceKey };
  return processSourceItem(env, source, item, { cacheCurrent: false });
}

async function listSubscriptions(env) {
  const out = [];
  let cursor = undefined;
  for (;;) {
    const page = await env.SUBS.list({ cursor, limit: 1000 });
    for (const key of page.keys || []) {
      if (!/^[0-9a-f]{64}$/i.test(key.name)) continue;
      const stored = await env.SUBS.get(key.name);
      if (!stored) continue;
      try {
        const parsed = JSON.parse(stored);
        const plain = await aesGcmDecrypt(env.SUBS_ENC_KEY, parsed.iv, parsed.ct);
        const sub = JSON.parse(plain).sub;
        if (sub && sub.endpoint) out.push(sub);
      } catch (e) {
      }
    }
    if (!page.list_complete) {
      cursor = page.cursor;
      continue;
    }
    return out;
  }
}

async function sendToAllSubscriptions(env, payload) {
  const subscriptions = await listSubscriptions(env);
  const results = { total: subscriptions.length, sent: 0, failed: 0, errors: [] };
  for (const subscription of subscriptions) {
    try {
      await sendNotification(subscription, JSON.stringify(payload));
      results.sent += 1;
    } catch (e) {
      results.failed += 1;
      results.errors.push({
        endpoint: subscription.endpoint,
        error: String(e && e.message ? e.message : e)
      });
    }
  }
  return results;
}

async function handleWebSubDelivery(env, rawBody, fallbackUrl = '') {
  const text = new TextDecoder().decode(rawBody);
  const item = await parseLatestFeedItem(text);
  if (!item || !item.title) return { ok: false, reason: 'unable_to_parse_feed_item' };
  return processSourceItem(env, {
    sourceKey: fallbackUrl ? `websub:${fallbackUrl}` : 'websub:unknown',
    sourceType: 'websub'
  }, item, { cacheCurrent: false });
}

async function handleWebhookDelivery(env, rawBody, contentType = '') {
  if (!contentType.includes('application/json')) return { ok: false, reason: 'unsupported_content_type' };
  const body = JSON.parse(new TextDecoder().decode(rawBody));
  if (!body || !body.title) return { ok: false, reason: 'missing_title' };
  const item = {
    title: body.title,
    description: body.body || '',
    summaryText: body.body || '',
    summaryHtml: body.bodyHtml || '',
    link: body.link || '',
    imageUrl: body.imageUrl || '',
    itemId: body.itemKey || body.id || body.link || '',
    publishedAt: body.publishedAt || new Date().toISOString()
  };
  return processSourceItem(env, {
    sourceKey: body.sourceKey || 'webhook:default',
    sourceType: 'webhook'
  }, item, { cacheCurrent: false });
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders
    }
  });
}

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
      const rawItems = (await getStateJson(env, HISTORY_KEY) || []).filter((item) => {
        const createdAt = item && item.createdAt ? Date.parse(item.createdAt) : 0;
        return createdAt && (now - createdAt) <= HISTORY_RETENTION_MS;
      }).sort((a, b) => Date.parse(b.createdAt || 0) - Date.parse(a.createdAt || 0));
      const items = await Promise.all(rawItems.map(async (item) => ({
        ...item,
        summaryText: cleanHistoryBodyText(item.summaryText),
        summaryHtml: item.summaryHtml
          ? await sanitizeSummaryHtml(item.summaryHtml, cleanHistoryBodyText(item.summaryText))
          : ''
      })));
      await putStateJson(env, HISTORY_KEY, rawItems);
      return json({
        ok: true,
        items
      });
    }

    if (request.method === 'POST' && url.pathname === '/subscribe') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const sub = await request.json();
      const endpoint = sub && sub.endpoint;
      if (!endpoint) return new Response('Bad Request', { status: 400 });

      const key = await sha256hex(endpoint);
      try {
        const existing = await env.SUBS.get(key);
        if (existing) {
          const parsed = JSON.parse(existing);
          const plainOld = await aesGcmDecrypt(env.SUBS_ENC_KEY, parsed.iv, parsed.ct);
          const objOld = JSON.parse(plainOld);
          const oldSub = objOld.sub;
          const sameEndpoint = oldSub.endpoint === sub.endpoint;
          const sameP256dh = oldSub.keys && sub.keys && oldSub.keys.p256dh === sub.keys.p256dh;
          const sameAuth = oldSub.keys && sub.keys && oldSub.keys.auth === sub.keys.auth;
          if (sameEndpoint && sameP256dh && sameAuth) {
            return json({ status: 'ok', updated: false });
          }
        }
      } catch (e) {
      }

      const plain = JSON.stringify({ sub, created: Date.now() });
      const enc = await aesGcmEncrypt(env.SUBS_ENC_KEY, plain);
      await env.SUBS.put(key, JSON.stringify({ iv: enc.iv, ct: enc.ct }));
      return json({ status: 'ok', updated: true });
    }

    if (request.method === 'POST' && url.pathname === '/unsubscribe') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const body = await request.json();
      if (!body || !body.endpoint) return new Response('Bad Request', { status: 400 });
      await env.SUBS.delete(await sha256hex(body.endpoint));
      return json({ status: 'deleted' });
    }

    if (request.method === 'POST' && url.pathname === '/send') {
      const apiKey = request.headers.get('x-api-key');
      if (!apiKey || apiKey !== env.SEND_API_KEY) return new Response('Unauthorized', { status: 401 });
      const body = await request.json();
      const endpoint = body && body.endpoint;
      if (!endpoint) return new Response('Bad Request', { status: 400 });

      const stored = await env.SUBS.get(await sha256hex(endpoint));
      if (!stored) return new Response('Not found', { status: 404 });

      const parsed = JSON.parse(stored);
      const plain = await aesGcmDecrypt(env.SUBS_ENC_KEY, parsed.iv, parsed.ct);
      const subscription = JSON.parse(plain).sub;

      try {
        await sendNotification(subscription, JSON.stringify(body.payload || {}));
        return json({ ok: true });
      } catch (e) {
        return new Response(String(e && e.message ? e.message : e), { status: 500 });
      }
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
        if (env.WEBSUB_SECRET) {
          const ok = await verifyWebhookSignature(request, rawBody, env.WEBSUB_SECRET);
          if (!ok) return new Response('Unauthorized', { status: 401 });
        }
        const fallbackUrl = url.searchParams.get('hub.topic') || '';
        const work = handleWebSubDelivery(env, rawBody, fallbackUrl);
        if (ctx && typeof ctx.waitUntil === 'function') {
          ctx.waitUntil(work);
        } else {
          await work;
        }
        return new Response(null, { status: 204 });
      }

      return new Response('Method Not Allowed', { status: 405 });
    }

    if (request.method === 'POST' && url.pathname === '/websub/subscribe') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const body = await request.json().catch(() => ({}));
      const hub = body.hub || env.WEBSUB_HUB_URL || '';
      const topic = body.topic || env.WEBSUB_TOPIC || '';
      const callback = body.callback || env.WEBSUB_CALLBACK_URL || `${url.origin}/websub`;
      const secret = body.secret || env.WEBSUB_SECRET || '';
      const leaseSeconds = body.lease_seconds || env.WEBSUB_LEASE_SECONDS || '864000';
      if (!hub || !topic || !callback) return new Response('Missing hub, topic, or callback URL', { status: 400 });

      const res = await fetch(hub, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formEncode({
          'hub.mode': 'subscribe',
          'hub.topic': topic,
          'hub.callback': callback,
          'hub.secret': secret,
          'hub.lease_seconds': leaseSeconds
        })
      });
      return json({ ok: res.ok, status: res.status, body: await res.text().catch(() => '') }, res.status);
    }

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
        body: formEncode({
          'hub.mode': 'unsubscribe',
          'hub.topic': topic,
          'hub.callback': callback
        })
      });
      return json({ ok: res.ok, status: res.status, body: await res.text().catch(() => '') }, res.status);
    }

    if (request.method === 'POST' && url.pathname === '/webhook') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const rawBody = await request.arrayBuffer();
      if (env.WEBHOOK_SECRET) {
        const ok = await verifyWebhookSignature(request, rawBody, env.WEBHOOK_SECRET);
        if (!ok) return new Response('Unauthorized', { status: 401 });
      }
      const work = handleWebhookDelivery(env, rawBody, request.headers.get('content-type') || '');
      if (ctx && typeof ctx.waitUntil === 'function') {
        ctx.waitUntil(work);
      } else {
        await work;
      }
      return new Response(null, { status: 204 });
    }

    if (request.method === 'GET' && url.pathname === '/rss/preview') {
      const feedUrl = url.searchParams.get('url') || env.POLL_URL || '';
      if (!feedUrl) return new Response('Missing feed URL', { status: 400 });
      const preview = await fetchFeedPreview(feedUrl);
      return json({
        ok: true,
        feedUrl,
        status: preview.status,
        contentType: preview.contentType,
        preview: preview.text.slice(0, 4000)
      });
    }

    if (request.method === 'POST' && url.pathname === '/rss/send') {
      const apiKey = request.headers.get('x-api-key');
      if (!apiKey || apiKey !== env.SEND_API_KEY) return new Response('Unauthorized', { status: 401 });

      const body = await request.json().catch(() => ({}));
      const feedUrl = body.url || env.POLL_URL || '';
      if (!feedUrl) return new Response('Missing feed URL', { status: 400 });

      const preview = await fetchFeedPreview(feedUrl);
      if (preview.status < 200 || preview.status >= 300) {
        return json({ ok: false, feedUrl, status: preview.status, error: 'Feed fetch failed' }, 502);
      }

      const item = await parseLatestFeedItem(preview.text);
      if (!item || !item.title) return new Response('Unable to parse latest feed item', { status: 422 });
      const scheduledFeedConfig = getScheduledFeedConfig(feedUrl);
      const normalizedItem = normalizeScheduledFeedItem(scheduledFeedConfig, item);
      const result = await processSourceItem(env, {
        sourceKey: scheduledFeedConfig?.sourceKey || feedUrl,
        sourceType: 'rss',
        lang: scheduledFeedConfig?.lang || ''
      }, normalizedItem, { cacheCurrent: false });
      return json({
        ok: !result.skipped && result.failed === 0,
        feedUrl,
        item: normalizedItem,
        ...result
      }, result.skipped ? 200 : (result.failed === 0 ? 200 : 207));
    }

    return env.ASSETS.fetch(request);
  },

  async scheduled(controller, env, ctx) {
    const work = (async () => {
      initializeVapid(env);
      if (controller.cron === '0 */2 * * *') {
        await processQWeatherRainAlert(env);
      } else if (controller.cron === '10 0 * * *') {
        for (const feedConfig of DEFAULT_RSS_SOURCES) {
          await refreshScheduledRssFeedState(env, feedConfig);
        }
      } else if (controller.cron === '30 0 * * *') {
        for (const feedConfig of DEFAULT_RSS_SOURCES) {
          const sourceKey = feedConfig.sourceKey;
          const item = await getStateJson(env, getSourceCurrentKey(sourceKey));
          if (item) {
            await processSourceItem(env, {
              sourceKey,
              sourceType: 'rss',
              lang: feedConfig.lang || ''
            }, item);
          }
        }
      }
    })();
    if (ctx && typeof ctx.waitUntil === 'function') {
      ctx.waitUntil(work);
    } else {
      await work;
    }
  }
};
