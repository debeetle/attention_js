import { setVapidDetails, sendNotification } from './pwanotify.js';

const SHANGHAI_TIME_ZONE = 'Asia/Shanghai';
const WIKIPEDIA_POTD_FEED_URL = 'https://en.wikipedia.org/w/api.php?action=featuredfeed&feed=potd&feedformat=atom';
const WIKIPEDIA_BASE_URL = 'https://en.wikipedia.org';
const HISTORY_KEY = 'history:items';
const HISTORY_LIMIT = 100;
const WIKIPEDIA_POTD_SOURCE_KEY = 'wikipedia-potd';

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

function shanghaiDateString(date = new Date()) {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: SHANGHAI_TIME_ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(date);
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
    return new URL(url, baseUrl || WIKIPEDIA_BASE_URL).toString();
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

function removeWikiNoise(str) {
  return (str || '')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<link[\s\S]*?\/?>/gi, ' ')
    .replace(/\u007f?['"`]*UNIQ--[\w-]+-QINU['"`]*\u007f?/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function stripTags(str) {
  return removeWikiNoise(
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
    return slice.slice(0, lastSentenceEnd + 1).trim();
  }
  return `${slice.trim()}...`;
}

function firstMatch(text, patterns) {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match && match[1]) return match[1].trim();
  }
  return '';
}

function parseLatestFeedItem(feedText) {
  const itemBlock = firstMatch(feedText, [
    /<item\b[^>]*>([\s\S]*?)<\/item>/i,
    /<entry\b[^>]*>([\s\S]*?)<\/entry>/i
  ]);
  if (!itemBlock) return null;

  const feedTitle = stripTags(firstMatch(feedText, [
    /<channel\b[^>]*>[\s\S]*?<title>([\s\S]*?)<\/title>/i,
    /<feed\b[^>]*>[\s\S]*?<title[^>]*>([\s\S]*?)<\/title>/i
  ]));
  const baseUrl = decodeXmlEntities(firstMatch(feedText, [
    /<link[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["'][^>]*\/?>/i,
    /<link[^>]*href=["']([^"']+)["'][^>]*\/?>/i
  ]));
  const title = stripTags(firstMatch(itemBlock, [
    /<title[^>]*>([\s\S]*?)<\/title>/i
  ]));
  const link = toAbsoluteUrl(decodeXmlEntities(firstMatch(itemBlock, [
    /<link>([\s\S]*?)<\/link>/i,
    /<link[^>]*href=["']([^"']+)["'][^>]*\/?>(?:<\/link>)?/i,
    /<guid[^>]*>(https?:[^<]+)<\/guid>/i,
    /<id[^>]*>(https?:[^<]+)<\/id>/i
  ])), baseUrl);
  const itemId = decodeXmlEntities(firstMatch(itemBlock, [
    /<id[^>]*>([\s\S]*?)<\/id>/i,
    /<guid[^>]*>([\s\S]*?)<\/guid>/i,
    /<link[^>]*href=["']([^"']+)["'][^>]*\/?>(?:<\/link>)?/i,
    /<link>([\s\S]*?)<\/link>/i
  ]));
  const publishedAt = decodeXmlEntities(firstMatch(itemBlock, [
    /<updated[^>]*>([\s\S]*?)<\/updated>/i,
    /<published[^>]*>([\s\S]*?)<\/published>/i,
    /<pubDate[^>]*>([\s\S]*?)<\/pubDate>/i
  ]));
  const decodedSummaryHtml = decodeXmlEntities(firstMatch(itemBlock, [
    /<description[^>]*>([\s\S]*?)<\/description>/i,
    /<content[^>]*>([\s\S]*?)<\/content>/i,
    /<summary[^>]*>([\s\S]*?)<\/summary>/i
  ]));
  const description = truncateToSentence(stripTags(firstMatch(decodedSummaryHtml, [
    /<p\b[^>]*>([\s\S]*?)<\/p>/i
  ]) || decodedSummaryHtml), 180);
  const imageUrl = toAbsoluteUrl(firstMatch(decodedSummaryHtml, [
    /<img[^>]*src=["']([^"']+)["'][^>]*>/i,
    /<media:content[^>]*url=["']([^"']+)["'][^>]*\/?>/i,
    /<media:thumbnail[^>]*url=["']([^"']+)["'][^>]*\/?>/i
  ]), baseUrl || link);
  const summaryHtml = sanitizeSummaryHtml(decodedSummaryHtml, description);

  return { feedTitle, title, link, description, summaryHtml, imageUrl, itemId, publishedAt };
}

function sanitizeSummaryHtml(summaryHtml, summaryText) {
  if (!summaryHtml) return summaryText ? `<p>${escapeHtml(summaryText)}</p>` : '';
  const firstParagraph = firstMatch(summaryHtml, [
    /<p\b[^>]*>([\s\S]*?)<\/p>/i
  ]);
  if (!firstParagraph) return summaryText ? `<p>${escapeHtml(summaryText)}</p>` : '';
  const sanitized = removeWikiNoise(firstParagraph)
    .replace(/\s(?:class|style|lang|dir|title|typeof|data-[^=]+)=["'][^"']*["']/gi, '')
    .replace(/href=(["'])(\/[^"']*)\1/gi, `href="${
      WIKIPEDIA_BASE_URL
    }$2"`)
    .replace(/href=(["'])(\/\/[^"']*)\1/gi, 'href="https:$2"');
  return `<p>${sanitized}</p>`;
}

function parseFeedEntries(feedText) {
  return Array.from(feedText.matchAll(/<entry\b[^>]*>([\s\S]*?)<\/entry>/gi)).map(match => match[1]);
}

function parseWikipediaPotdFeed(feedText) {
  const entries = parseFeedEntries(feedText);
  if (entries.length === 0) return null;

  const parsedEntries = entries.map((entryBlock) => {
    const title = stripTags(firstMatch(entryBlock, [
      /<title[^>]*>([\s\S]*?)<\/title>/i
    ]));
    const link = toAbsoluteUrl(decodeXmlEntities(firstMatch(entryBlock, [
      /<link[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["'][^>]*\/?>/i,
      /<link[^>]*href=["']([^"']+)["'][^>]*\/?>/i,
      /<id[^>]*>(https?:[^<]+)<\/id>/i
    ])));
    const updated = firstMatch(entryBlock, [
      /<updated[^>]*>([\s\S]*?)<\/updated>/i,
      /<published[^>]*>([\s\S]*?)<\/published>/i
    ]);
    const decodedSummaryHtml = decodeXmlEntities(firstMatch(entryBlock, [
      /<summary[^>]*>([\s\S]*?)<\/summary>/i,
      /<content[^>]*>([\s\S]*?)<\/content>/i
    ]));
    const imageUrl = toAbsoluteUrl(firstMatch(decodedSummaryHtml, [
      /<img[^>]*src=["']([^"']+)["'][^>]*>/i
    ]));
    const summaryText = truncateToSentence(stripTags(firstMatch(decodedSummaryHtml, [
      /<p\b[^>]*>([\s\S]*?)<\/p>/i
    ]) || decodedSummaryHtml), 180);
    const summaryHtml = sanitizeSummaryHtml(decodedSummaryHtml, summaryText);
    const date = updated ? updated.slice(0, 10) : '';

    return {
      date,
      title,
      link,
      summaryText,
      summaryHtml,
      imageUrl,
      updatedAt: updated
    };
  }).filter(item => item.title && item.updatedAt);

  if (parsedEntries.length === 0) return null;
  parsedEntries.sort((a, b) => a.updatedAt.localeCompare(b.updatedAt));
  return parsedEntries.at(-1);
}

function buildNotificationPayload(item) {
  return {
    web_push: 8030,
    notification: {
      title: item.title,
      body: item.summaryText || item.description || item.feedTitle || 'New item',
      navigate: item.link || WIKIPEDIA_BASE_URL,
      silent: false,
      app_badge: '1'
    }
  };
}

function buildHistoryItem(source, item, itemKey, sentAt = new Date().toISOString()) {
  return {
    id: `${source.sourceKey}:${itemKey}`,
    sourceKey: source.sourceKey,
    sourceType: source.sourceType,
    sourceLabel: source.sourceLabel,
    title: item.title,
    body: item.summaryText || item.description || '',
    link: item.link || '',
    imageUrl: item.imageUrl || '',
    publishedAt: item.publishedAt || item.updatedAt || '',
    createdAt: sentAt
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

async function getStateJson(env, key) {
  const raw = await env.SUBS.get(key);
  if (!raw) return null;
  return JSON.parse(raw);
}

async function putStateJson(env, key, value) {
  await env.SUBS.put(key, JSON.stringify(value));
}

async function appendHistoryItem(env, historyItem) {
  const history = await getStateJson(env, HISTORY_KEY) || [];
  const next = [historyItem, ...history.filter(item => item.id !== historyItem.id)].slice(0, HISTORY_LIMIT);
  await putStateJson(env, HISTORY_KEY, next);
  return next;
}

async function refreshWikipediaPotdState(env) {
  const preview = await fetchFeedPreview(WIKIPEDIA_POTD_FEED_URL);
  if (preview.status < 200 || preview.status >= 300) {
    throw new Error(`POTD feed fetch failed: ${preview.status}`);
  }

  const potd = parseWikipediaPotdFeed(preview.text);
  if (!potd) throw new Error('Unable to parse Wikipedia POTD feed');

  const current = await getStateJson(env, getSourceCurrentKey(WIKIPEDIA_POTD_SOURCE_KEY));
  const changed = !current ||
    current.date !== potd.date ||
    current.title !== potd.title ||
    current.link !== potd.link ||
    current.summaryText !== potd.summaryText ||
    current.imageUrl !== potd.imageUrl;

  if (changed) {
    await putStateJson(env, getSourceCurrentKey(WIKIPEDIA_POTD_SOURCE_KEY), potd);
  }

  return { potd, changed };
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
  const historyItem = buildHistoryItem(source, item, itemKey);
  await appendHistoryItem(env, historyItem);
  return {
    skipped: false,
    sourceKey: source.sourceKey,
    item,
    itemKey,
    ...result
  };
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
  const item = parseLatestFeedItem(text);
  if (!item || !item.title) return { ok: false, reason: 'unable_to_parse_feed_item' };
  return processSourceItem(env, {
    sourceKey: fallbackUrl ? `websub:${fallbackUrl}` : `websub:${item.feedTitle || 'unknown'}`,
    sourceType: 'websub',
    sourceLabel: item.feedTitle || fallbackUrl || 'WebSub'
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
    link: body.link || '',
    imageUrl: body.imageUrl || '',
    itemId: body.itemKey || body.id || body.link || '',
    publishedAt: body.publishedAt || new Date().toISOString(),
    feedTitle: body.sourceLabel || body.sourceKey || 'Webhook'
  };
  return processSourceItem(env, {
    sourceKey: body.sourceKey || 'webhook:default',
    sourceType: 'webhook',
    sourceLabel: body.sourceLabel || body.sourceKey || 'Webhook'
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
      const items = await getStateJson(env, HISTORY_KEY) || [];
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

      const item = parseLatestFeedItem(preview.text);
      if (!item || !item.title) return new Response('Unable to parse latest feed item', { status: 422 });
      const result = await processSourceItem(env, {
        sourceKey: `rss:${feedUrl}`,
        sourceType: 'rss',
        sourceLabel: item.feedTitle || feedUrl
      }, item, { cacheCurrent: false });
      return json({
        ok: !result.skipped && result.failed === 0,
        feedUrl,
        item,
        ...result
      }, result.skipped ? 200 : (result.failed === 0 ? 200 : 207));
    }

    return env.ASSETS.fetch(request);
  },

  async scheduled(controller, env, ctx) {
    const work = (async () => {
      initializeVapid(env);
      if (controller.cron === '5 0 * * *') {
        await refreshWikipediaPotdState(env);
      } else if (controller.cron === '30 0 * * *') {
        const potd = await getStateJson(env, getSourceCurrentKey(WIKIPEDIA_POTD_SOURCE_KEY));
        if (potd) {
          await processSourceItem(env, {
            sourceKey: WIKIPEDIA_POTD_SOURCE_KEY,
            sourceType: 'rss',
            sourceLabel: 'Wikipedia POTD'
          }, potd);
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
