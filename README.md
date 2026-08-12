# P2P Chat

部署在 Cloudflare Workers 的浏览器聊天原型。

- 私聊：浏览器通过 WebRTC DataChannel 直连，Workers 只保存 10 分钟的 SDP 信令与在线状态。
- 群聊：每条消息都在浏览器内用一次性 AES-GCM 内容密钥加密；内容密钥再以每位收件人的 ECDH 公钥单独封装。所有收件人回执确认拿到密文前，Workers 不会返回任何密钥包。
- 账户：邮箱验证码注册/登录。Workers 通过 Cloudflare Email Service 原生 `send_email` 绑定发出邮件，验证码只在 KV 中保存 10 分钟。
- D1：用户邮箱、公钥、群组和成员关系。
- KV：短期信令、在线状态、24 小时的群消息密文与回执。

## 部署

1. `npm install`
2. `npx wrangler d1 create p2p-chat`，把输出的 ID 填到 `wrangler.jsonc`。
3. `npx wrangler kv namespace create EPHEMERAL`，把 ID 填到 `wrangler.jsonc`。
4. `npx wrangler d1 migrations apply p2p-chat --remote`
5. Cloudflare 控制台打开 **Compute → Email Service → Email Sending**，接入你在 Cloudflare DNS 托管的发件域名；将 `wrangler.jsonc` 的 `MAIL_FROM` 改为该域名的地址，例如 `P2P Chat <noreply@chat.example.com>`。
6. `npm run deploy`

本地开发使用 `npx wrangler d1 migrations apply p2p-chat --local` 后执行 `npm run dev`。

## 安全边界

浏览器密钥仅在本机 LocalStorage 保存，服务端只保存公钥与令牌哈希。验证邮箱后在新设备登录会轮换该账户的设备公钥，因此旧设备将不能继续解密后续消息；多设备同步需要单独实现设备管理与密钥包。私聊依赖双方网络允许 WebRTC；严格 NAT 环境需要另行配置 TURN。KV 适合临时中继而非强一致协调，因此界面会反复轮询并重试回执；如需大规模强一致群组投递，应把回执栅栏迁移至 Durable Object。
