const webpush = require('web-push');
const fs = require('fs');

// 手动读取 .env 文件（不需要垃圾包）
if (fs.existsSync('.env')) {
    const envContent = fs.readFileSync('.env', 'utf-8');
    envContent.split('\n').forEach(line => {
        const [key, value] = line.split('=');
        if (key && value) process.env[key.trim()] = value.trim();
    });
}

// 配置
const PUBLIC_VAPID_KEY = process.env.PUBLIC_VAPID_KEY;
const PRIVATE_VAPID_KEY = process.env.PRIVATE_VAPID_KEY;
webpush.setVapidDetails('mailto:nobody@example.com', PUBLIC_VAPID_KEY, PRIVATE_VAPID_KEY);

const subscription = JSON.parse(fs.readFileSync('subs.json'));

// 发送消息
const payload = JSON.stringify({
    "web_push": 8030,
    "notification": {
        "title": "喝水",
        "body": process.argv[2] || "记得喝水", // 允许带参数发送
        "navigate": "https://suckless.org",
        "app_badge": "1",
        "silent": false
    }
});

webpush.sendNotification(subscription, payload)
