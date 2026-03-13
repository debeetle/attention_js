const https = require('https');
const fs = require('fs');
const url = require('url');
const path = require('path');
const webpush = require('web-push');

// 手动读取 .env 文件
if (fs.existsSync('.env')) {
    const envContent = fs.readFileSync('.env', 'utf-8');
    envContent.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) process.env[key.trim()] = value.trim();
    });
}

const PUBLIC_VAPID_KEY = process.env.PUBLIC_VAPID_KEY
const PRIVATE_VAPID_KEY = process.env.PRIVATE_VAPID_KEY

let ICON_PNG_DATA_URI = '';
try {
    const iconPngBase64 = fs.readFileSync(path.join(__dirname, 'icon.png')).toString('base64');
    ICON_PNG_DATA_URI = `data:image/png;base64,${iconPngBase64}`;
} catch (e) {
}

webpush.setVapidDetails('mailto:nobody@example.com', PUBLIC_VAPID_KEY, PRIVATE_VAPID_KEY);

// 内存中的订阅信息
let savedSubscription = null;
const SUBS_FILE = 'subs.json';

// 如果文件存在，就读取文件并覆盖 savedSubscription
if (fs.existsSync(SUBS_FILE)) {
    try {
        savedSubscription = JSON.parse(fs.readFileSync(SUBS_FILE));
    } catch (e) {
    }
}

// SSL 配置 
const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
};

// ================= 服务器逻辑 =================
const server = https.createServer(options, (req, res) => {
    const parsedUrl = url.parse(req.url, true);

    // 允许跨域
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // API 1: 接收订阅信息
    if (req.method === 'POST' && parsedUrl.pathname === '/subscribe') {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
            try {
                const newSubscription = JSON.parse(body);

                // 只有当订阅信息发生变化时才写入文件
                if (!savedSubscription || JSON.stringify(savedSubscription) !== JSON.stringify(newSubscription)) {
                    savedSubscription = newSubscription;
                    fs.writeFileSync(SUBS_FILE, JSON.stringify(savedSubscription));
                }

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ status: 'ok' }));
            } catch (e) {
                res.writeHead(400);
                res.end(JSON.stringify({ error: 'Invalid JSON' }));
            }
        });
        return;
    }

    // 静态文件服务 (替代 http-server)
    let filePath = '.' + req.url;
    if (filePath === './') filePath = './index.html';

    // 安全检查：禁止访问敏感文件
    const forbiddenFiles = ['./pwanotify.js', './send.js', './.env', './subs.json', './key.pem', './cert.pem', './package.json', './package-lock.json'];
    if (forbiddenFiles.includes(filePath) || filePath.includes('node_modules')) {
        res.writeHead(403);
        res.end('403 Forbidden');
        return;
    }

    const extname = String(path.extname(filePath)).toLowerCase();
    const mimeTypes = {
        '.html': 'text/html',
        '.js': 'text/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.webmanifest': 'application/manifest+json',
        '.png': 'image/png',
        '.jpg': 'image/jpg',
        '.svg': 'image/svg+xml'
    };

    const contentType = mimeTypes[extname] || 'application/octet-stream';

    fs.readFile(filePath, (error, content) => {
        if (error) {
            res.writeHead(404);
            res.end();
        } else {
            // 运行时把 icon.png 注入为 Base64，避免 iOS 在自签证书场景下二次请求图标失败
            if (ICON_PNG_DATA_URI && filePath === './index.html') {
                let html = content.toString('utf-8');
                html = html.replace(/<link\s+rel="icon"[^>]*>/i, `<link rel="icon" type="image/png" href="${ICON_PNG_DATA_URI}">`);
                html = html.replace(/<link\s+rel="apple-touch-icon"[^>]*>/i, `<link rel="apple-touch-icon" href="${ICON_PNG_DATA_URI}">`);
                content = Buffer.from(html, 'utf-8');
            }

            if (ICON_PNG_DATA_URI && filePath === './manifest.webmanifest') {
                try {
                    const manifest = JSON.parse(content.toString('utf-8'));
                    manifest.icons = [
                        {
                            src: ICON_PNG_DATA_URI,
                            sizes: '192x192',
                            type: 'image/png'
                        },
                        {
                            src: ICON_PNG_DATA_URI,
                            sizes: '512x512',
                            type: 'image/png'
                        },
                        {
                            src: ICON_PNG_DATA_URI,
                            sizes: '180x180',
                            type: 'image/png'
                        }
                    ];
                    content = Buffer.from(JSON.stringify(manifest, null, 2), 'utf-8');
                } catch (e) {
                }
            }

            // 关键：PWA 页面/脚本/manifest 禁止强缓存，避免更新不生效
            let cacheControl = 'public, max-age=3600';
            if (extname === '.html' || extname === '.js' || extname === '.webmanifest' || extname === '.json') {
                cacheControl = 'no-store, no-cache, must-revalidate, max-age=0';
            }

            res.writeHead(200, {
                'Content-Type': contentType,
                'Cache-Control': cacheControl,
                'Pragma': 'no-cache',
                'Expires': '0',
                'Access-Control-Allow-Origin': '*'
            });
            res.end(content, 'utf-8');
        }
    });
});

const PORT = 8000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`notifing`);
});
