---
name: http-request-smuggling
description: HTTP 请求走私（CL.TE / TE.CL / TE.TE / H2.CL / H2.TE）与请求隧道化的识别和利用。在存在反向代理/负载均衡 + 后端不一致解析、或 CDN 前置时使用。
version: 1.0.0
---

# HTTP 请求走私（Request Smuggling）

走私的本质是**两个 HTTP 解析器对"这个请求到哪里结束"意见不一致**。前端（代理/CDN/LB）与后端对 `Content-Length`(CL) 与 `Transfer-Encoding`(TE) 的处理差异，让攻击者可以在一条连接上把第二个请求"藏"进第一个请求里，由后端执行。

前置条件：前后端之间**复用连接**（keep-alive）。HTTP/2 前端 + HTTP/1.1 后端是最常见的可走私面（H2.CL / H2.TE）。

## 1. 先判断能不能走私（不是所有差异都可利用）

用一条**会因解析差异而超时**的探测请求。核心手法：制造"前端认为请求已结束、后端还在等"或反之，观察**响应时间异常（超时 ~5s+）**与后续请求被污染。

- 只是 headers 差异（如 `Transfer-Encoding: xchunked` 被后端忽略）→ 不构成走私。
- 差异导致**消息边界错位** + **连接复用** → 可走私。

先确认：目标是否 302/换站、是否 CDN 前置（看 `server`/`cf-ray`/`x-cache`）、是否 HTTP/2 可达（`curl --http2`）。

## 2. 四类构造

统一用 `\r\n`（真实 CRLF，不能用 `\n`）；长度按**字节**精确计算。

### CL.TE —— 前端信 CL，后端信 TE

```
POST / HTTP/1.1
Host: TARGET
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
前端读 13 字节就收工；后端读到 `0\r\n\r\n` 认为 chunk 结束，`SMUGGLED` 留在缓冲区成为下一个请求的开头。

### TE.CL —— 前端信 TE，后端信 CL

```
POST / HTTP/1.1
Host: TARGET
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```
后端按 CL 只读 3 字节（`8\r\n`），剩下的 `SMUGGLED` 成为下个请求。

### TE.TE —— 双方都支持 TE，但一方会被混淆

用畸形 TE 头让一方忽略、一方保留（试探哪一侧更宽容）：

```
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding : chunked          ← 冒号前有空格
Transfer-Encoding:\tchunked
Transfer-encoding: chunked
Transfer-Encoding: chunked, identity
X: X
Transfer-Encoding: chunked

```
逐个试，配合上两节的 CL/TE 正文构造，找出"哪一侧被说服"。

### H2.CL / H2.TE —— HTTP/2 降级到 HTTP/1.1 的后端

前端说 HTTP/2（无 TE、有 `content-length` 伪头），后端按 HTTP/1.1 重新拼装。常见两种：

- **H2.CL**：发一个 HTTP/2 请求，`content-length: 0`，但正文里带完整第二个请求。若前端信任 h2 的 CL 而把正文原样透给后端 → 后端把正文当请求执行。
- **H2.TE**：HTTP/2 请求里塞 `transfer-encoding: chunked` 头。按 RFC 该头在 h2 里非法应被拒绝，但不少代理会把它透传到 h1 后端。

工具里最省事：`h2c` / Burp 的 HTTP/2 走私插件 / `curl --http2` 手工构造。

## 3. 证明与放大

走私一旦成立，逐级放大（每级都要真实证据）：

1. **证明错位**：走私一个指向不存在路径的请求，看它是否"提前"出现在下一个正常请求的响应里（响应队列错位）。
2. **命中前端缓存**：走私 `GET /static/x.js` 让后端把它当作正常请求处理，若前端缓存把**别人的响应**发给你 → 缓存投毒 / 定向打用户。
3. **绕过前端鉴权**：前端只校验 `POST /admin` 的路径，走私一个 `GET /admin` 由后端执行 → 越权访问管理面。
4. **捕获他人请求**：走私一个"等待正文"的请求，把下一个用户的完整请求（含 Cookie/Token）吞进你的响应里 → 会话劫持证据。

## 4. 常见误判

| 现象 | 真相 |
| --- | --- |
| 发畸形 TE 后返回 400/501 | 前端直接拒绝 → 该入口不可走私（换路径/Host/协议版本再试） |
| 响应时间抖动但无错位 | 可能只是后端慢/重试，不构成走私 |
| 单条连接复现失败，压测并发才成功 | 走私对连接池状态敏感；要记录**确切的连接序列**（同一 TCP 连接上的请求顺序）否则不可复现 |

复现证据要写清：**同一条 keep-alive 连接**上的请求序列、原始报文（含 CRLF 的可视化）、后端执行了什么。用 `traffic_search`/`traffic_get` 取原文，`traffic_curl` 导出时可加 `--no-keepalive` 说明此时不适用。

## 5. 工具

- `h2spec`（探 h2 合规性）、`smuggler.py`（自动探测 CL.TE/TE.CL/H2.CL/H2.TE）
- Burp「HTTP Request Smuggler」扩展：内置扫描 + 变异
- `curl --http2 -H 'transfer-encoding: chunked' --data-binary @payload.txt` 手工验证

工具只是加速；报告里必须有**手工可复现的原始报文**，否则不算确认漏洞。
