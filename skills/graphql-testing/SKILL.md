---
name: graphql-testing
description: GraphQL 端点侦察、内省、IDOR/批量越权、注入、复杂度攻击与信息泄露。在发现 /graphql、/api/graphql、Apollo/Yoga/Hasura 指纹时使用。
version: 1.0.0
---

# GraphQL 安全测试

GraphQL 的"一个端点承载全部数据"让测试重点从"找接口"变成"找字段与权限边界"。核心四步：确认端点 → 内省拿 schema → 按字段逐个测越权 → 打注入/复杂度。

## 1. 确认端点与指纹

常见路径：`/graphql`、`/api/graphql`、`/v1/graphql`、`/graphiql`、`/playground`、`/query`、`/gql`。
指纹：响应含 `"errors":[{"message":"..."}]`、`GET /graphql?query={__typename}` 返回 `{"data":{"__typename":"Query"}}`、CORS 头 `Access-Control-Allow-*` 宽松、`Apollo-Server`/`graphql-yoga`/`Hasura` 头。

```
GET /graphql?query={__typename}
POST /graphql  {"query":"{__typename}"}
```

## 2. 内省

标准内省（若被禁用，见 §2.1 绕过）：

```graphql
{__schema{queryType{name} mutationType{name} subscriptionType{name}
  types{name kind fields{name type{name kind ofType{name kind ofType{name}}}}
        args{name type{name}}}
  directives{name}}}
```

抓到 schema 后转成本地文档：`graphql-introspection-json-to-sdl.py` / `graphql-voyager`，或用 `graphql-cop`、`InQL`（Burp）自动生成测试用例。

### 2.1 内省被禁时的取 schema 手段
- `__type(name:"User"){name fields{name type{name}}}` —— 部分部署只拦 `__schema`，不拦 `__type`。
- 错误回显 + 字段建议：故意写错字段名，`"Did you mean \"email\"?"` 会把真实字段吐出来（逐个套）。
- IDE/graphiql 静态资源里的 operation 名、Apollo persisted query 清单（`apq`）。
- 前端 JS bundle 里的 `.graphql` 片段 / `gql\`...\`` 模板字符串。

## 3. 权限与对象级授权（IDOR 是 GraphQL 最大的洞）

GraphQL 常见的授权错误：**只校验 Query 层，不校验字段层**；或依赖前端隐藏字段。

测法：
1. 用 A 账号取自己对象，记下 id；用 B 账号（低权）查 A 的 id → 是否返回数据（BOLA/IDOR）。
2. **字段级**：`User` 类型里 `password`/`apiToken`/`internalNotes`/`ssn` 等字段，正常 UI 不展示，但 schema 里有 → 直接查。
3. **嵌套穿透**：`{ user(id:1){ email orders { paymentMethods { cardNumber } } } }` —— 父级有权限，叶子没有。
4. **mutation 越权**：`updateUser(id:OTHER, role:"admin")` / `deletePost(id:OTHER)`。
5. **批量/别名放大（Batching）**：单请求里用别名并发 100 个对象，配合弱口令字典爆破绕过速率限制：
```graphql
mutation { a1:login(u:"admin",p:"1"){token} a2:login(u:"admin",p:"2"){token} ... }
```
6. **接口级联**：`node(id:...)`（Relay 全局 ID）遍历所有类型；`__typename` 探测隐藏类型。

## 4. 注入

- **SQL/NoSQL 注入**：字段参数接受字符串时按常规注入测（`id: "1'"`、`filter: {name: {"$ne": null}}`）。
- **服务端模板/表达式**：少数 resolver 把参数塞进模板。
- **SSRF**：`importUrl`/`fetchUrl`/`webhook`/`avatarFromUrl` 一类字段直接收 URL → 打内网。
- **命令注入**：字段名/参数被拼进系统命令的（PDF 生成、图像处理）。
- **复杂度攻击（DoS）**：深嵌套查询 `{a{a{a{a{...}}}}`、字段重复放大、`@include(if:true)` 递归片段 → 单请求拖垮后端。报告里按 DoS 类记，不夸大。

## 5. 其他高价值点

- **CORS**：`Access-Control-Allow-Origin: *` + `Allow-Credentials: true` → 跨站读取。
- **GET 方式**：允许 `GET /graphql?query=` → 可被 CSRF/图片标签触发（写操作若也能 GET 则是 CSRF）。
- **持久化查询/APQ**：若允许任意 `sha256Hash` 注册新查询，等于绕过前端限流。
- **订阅（subscription）**：WebSocket 鉴权常缺失 → 未授权订阅他人事件（`ws://` + `subscriptions-transport-ws`）。
- **错误信息泄露**：堆栈、SQL、内部域名。

## 6. 工具

```
# 探测 + 内省（无需安装）
curl -s -X POST http://TARGET/graphql -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'

# 常用工具
graphql-cop -t http://TARGET/graphql        # 通用安全检查
graphw00f -d -t http://TARGET/graphql       # 引擎指纹（决定绕过手法）
InQL（Burp 插件）                            # 内省 → 扫描
clairvoyance                                 # 内省被禁时的字段枚举（词表+错误建议）
```
请求统一走平台 `http_request`（自动落流量），复现用 `traffic_get` / `traffic_curl`。
