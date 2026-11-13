# Foxker / HotkerArteX 与 antifox 的功能差距分析

对比基线：`hotker/antifox` `main` @ `070f798`（v2.0.3），本仓库 `main` @ `25f3f6a`（v3.1.0）。

> 放在仓库根目录（而非 `docs/`）：`.gitignore` 里 `/docs/` 是刻意排除的本地设计文档区，这份是要长期跟踪的规划，得进版本库。
结论按「对交付/安全/自主性的影响」排序，不按代码量排序。

## 一、关系判断

两边同源（都源自 ARTEX），但**已经不是「谁落后」的关系**：

| 维度 | antifox | Foxker（本仓库） |
| --- | --- | --- |
| 数据库表 | 45 | 54（其中 21 张是上游没有的） |
| API 路由 | 193 | 272 |
| 前端页面 | 24 | 29 |
| Go 非测试代码 | 43,946 行 | 71,604 行 |
| Go 测试文件 | 28 个 | 190 个 |

上游有、我们没有的**只剩 7 组**（见下）；我们有、上游没有的是一整个量级的差异
（任务归档、旁问、多通道通知、手动复测、资产级拦截、约束注入、LLM 录制、命令页、
工作空间页、任务模板/分类/关系、覆盖图……）。

所以真正的缺口集中在 antifox v2.0 那一轮「交付 + 权限 + 国际化」的工程化投入上。

---

## 二、尚缺的能力（按优先级）

### P0 — 多用户权限（RBAC）

**现状**：单用户。用户名固定 `Foxker`（兼容 `ARTEX`），密码哈希存在 `settings` 表，
JWT `sub` 恒为 `"Foxker"`，7 天固定有效期，无用户表、无角色、无权限、无会话吊销粒度。

**上游**：`rbac_users / rbac_roles / rbac_permissions / rbac_role_permissions / rbac_user_roles`
五张表 + 权限目录（`module:action`，31 项）+ 四个系统角色（admin/operator/auditor/viewer）
+ 资源级 scope（all/assigned/own）+ 可视化权限矩阵 + `rbac.enforce` 开关。

**为什么是 P0**：渗透平台的「谁能打哪个目标」是合规底线。现在任何拿到口令的人都是全域 admin；
报告里也没有「谁确认的」这一层责任人信息。

**顺带能补上的**：`token_version`（改密/停用即吊销全部会话）+ 滑动续期 + 空闲超时。
我们现在只有一个全局 `tokenGen`，改密能踢掉所有人——但无法只踢某个用户。

### P1 — 审计日志持久化与可查

**现状**：`[audit]` 行进标准日志 → `server_logs` 环形缓冲。
**有** method/path/ip/status/耗时；**没有** actor、category、action、result 结构化字段，
也没有独立的查询接口与页面（现有「日志」页是给后端日志用的，混杂在一起）。

**上游**：`audit_logs` 表 + `GET /api/audit/logs` + 按 actor/category 筛选。
**为什么是 P1**：与 RBAC 同源——没有 actor 的审计在多人环境里没有证据价值。做完 RBAC 后
这一项才有意义，所以排在它后面。

### P1 — 漏洞 AI 富化（结构化交付字段）

**现状**：`findings.cvss / impact / remediation` 三个**自由文本**列（上一轮我加的），
人工填写，报告直接渲染。

**上游**：`finding_enrichment` 表，字段是结构化的——`cvss_score`(float) + `cvss_vector`
+ `cvss_metrics`(map) + `description[]` + `test_process[]`（分步的 block）+ `risk_analysis[]`
+ `remediation[]`；由一次 LLM 调用生成，**异步任务 + status 轮询**（`POST /enrich` 立即返回
`analyzing`，`GET /enrich/status` 取结果，重复点击去重到同一个 job）。

**差距实质**：我们缺的是「CVSS 三要素 + 分步测试过程」的结构，而不是少一个按钮。
自由文本无法生成 CVSS 向量、也无法在报告里做「测试过程」表格。

### P1 — 证据截图（图片进 docx）

**现状**：报告的「证据」只有文字与流量报文。`report/docx.go` **完全不支持图片**（无
`word/media` 部件、无 `<w:drawing>`）。

**上游**：`finding_evidence` 表 + 上传接口（16MB/5000 万像素上限，带解压炸弹防护）+
按步骤归属（`step_index`）+ 自动图注 + 报告内嵌图片并按磁盘路径引用。

**为什么重要**：给客户的报告里，截图是「不可辩驳」的那一类证据。报文比截图更硬，
但客户的评审习惯是看图。

### P2 — 报告模板（多套预设）

**现状**：单份组织级设置（`report_settings`，单行表）：出具方/客户/密级/语言/人员/版本。
**上游**：`report_templates` 多套命名模板（含 logo 路径、CVSS 版本、locale），新建报告时选用。

差距不大（我们现在改设置也能换），但如果要「同一批漏洞出两种口径的报告」（内部版/客户版），
现在只能来回改设置。

### P2 — 会话漏洞补录（extract-findings）

**现状**：没有。agent 没写 `report_finding` 的发现就永远不在库里。

**上游**：`POST /api/tasks/{id}/extract-findings` —— 把会话转录 + 探索图里的 fact 一起喂给
LLM，回填成 finding（带去重标签与服务端兜底）。这是「跑完一轮发现漏记」的补救通道。

### P3 — MCP / Skill 用量可观测

**现状**：`skill_usage` / `tool_usage` 表**已有**且在 skills 页展示（比上游的
`skill_stats` 字段更全：带 task/session/args_len/found）。缺的是 MCP 侧的用量与
`POST /api/mcp/{id}/health` 健康检查端点。

### P3 — 全站三语国际化

**现状**：**零 i18n**。全站中文硬编码（我刚加的页面也是中文）。
**上游**：`i18next` + `react-i18next`，44 个组件用 `useTranslation`，三份 locale 共 5823 行。

注意：我们的**报告**已经是三语（zh-CN / zh-TW / en-US，`report/docxbuild.go`），
缺的是**界面**。如果对外交付需要英文控制台，这是必做项；否则可以不做。

---

## 三、我们领先的部分（避免误判为「要补」）

- 任务归档 / 任务模板 / 任务分类 / 任务关系 / 任务约束注入 / 任务级 LLM 链
- 旁问（side question）独立会话、多通道通知（含投递重试）、手动复测（finding_retests）
- 资产级拦截规则、拦截审批详情、抓包范围隔离（`capture.Scope`）、敏感路径守卫
- LLM 录制（llmrec）与按模型计费视图、命令页、工作空间页、覆盖图
- 交互式 shell（shell_open/shell_session）、冷图摘要（cold-digest）、上下文压缩与
  「渗透态摘要」、意图去重闸门、停滞告警、模型路由（deep/economy/balanced）
- 报告：**纯 Go 生成 docx**（上游依赖 python3 + python-docx 子进程）
- 知识库：**零外部依赖抽取**（.docx 用 archive/zip + encoding/xml，上游调 python-docx）

---

## 四、建议的实施顺序

1. **RBAC**（P0）：用户/角色/权限表 + 权限目录 + 中间件 + 用户管理页 + 权限矩阵页。
   同时把 `token_version` 与滑动续期做进去——它们本来就是同一件事。
2. **审计持久化**（P1）：`audit_logs` + 从 `accessCtx` 取 actor + 查询接口 + 页面筛选。
   依赖 1 的 actor 才能落地，所以必须紧随其后。
3. **AI 富化**（P1）：`finding_enrichment` 结构化字段 + 异步 job + 状态轮询 + 报告渲染
   用的 CVSS 向量与「测试过程」表格。
4. **证据截图**（P1）：上传/存储/展示 + docx 图片部件（`word/media` + `<w:drawing>`
   + EMU 尺寸计算）。
5. 报告模板（P2）→ 会话补录（P2）→ MCP 健康与用量（P3）→ i18n（P3，按是否需要英文控制台决定）。

每项都会带上与仓库现有风格一致的测试（真 PG + 纯函数不变量），并在实现里保持
「不因新功能而让现有部署不可用」这条底线。