package agent

// 本文件是 HotkerArteX 对 worker 的【代码固定注入】增强（段 [B2]）：与 trafficTool 同级，
// 不写进 DB、不可被提示词编辑掉。理由很直接——下面这两条纪律每次改动都有人用提示词
// "优化"掉，但它们恰好决定了证据链成不成立：
//
//   1. 发包方式：结构化发包（http_request）而不是随手 curl。只有前者能保证每条探测
//      都落进流量库、能被 report_finding 的 reproduction.steps[].exchange_id 引用。
//   2. 复现闭环：先把攻击链跑通，再把它写成 steps；写 steps 时请求响应必须逐字取自
//      真实报文，不许"凭记忆重写"。这一步做对，报告就能被人从零复现。
//
// 注入位置：workerSystem 的段 [B] 之后（见 workerSystem），保证在 system 里常驻、
// 抗 compaction，且不受 DB 正文编辑影响。

// workerEvidenceBlock 是段 [B2]：发包与取证纪律。
func workerEvidenceBlock(hasTraffic bool, hasHTTPReq bool) string {
	if !hasHTTPReq && !hasTraffic {
		return ""
	}
	b := "\n\n**发包与取证纪律（代码固定，务必遵守）**：\n"
	if hasHTTPReq {
		b += "- 对目标发 HTTP 请求**优先用 http_request**（结构化：方法/头/体/表单/JSON/Cookie 显式可控），而不是 Bash+curl。它不是「更好看的 curl」——它默认经记录代理出网，每一条请求都会落进流量库；只有落库的请求才能被复现步骤引用、才能在报告里点开看原文。\n" +
			"- 需要 curl 特有/链式的手法（--path-as-is、多步管道、nc 交互）才用 Bash；用 Bash 时也必须走记录代理（Bash 环境已预置代理与 CA，直接 curl 即可，别手动 -x/-k）。\n"
	}
	if hasTraffic {
		b += "- **先查流量、再发请求**：同一个 URL 已经打过就先 traffic_search 找它，必要时 traffic_get 看原文——不要重复发同一条请求浪费预算，也不要凭记忆复述响应。\n" +
			"- **复现必须落到真实报文**：report_finding 的 reproduction.steps[].request/response 要逐字取自你实际发过的请求与拿到的响应（traffic_get 的原文就是最准的来源）；能拿到 exchange id 时一并带上。写「大概是这样」的复现等于让报告作废。\n"
	}
	b += "- **复现要结构化落库**：report_finding 的 reproduction 字段填 entry_point（方法+URL）/ prerequisites（账号与前置，需账号时写清如何注册）/ steps（有序，每步 request 与 response 逐字取自真实报文）/ provenance（链条来源）。只写一段自由文本证据，报告里就没有逐步复现路径，工程师只能自己猜怎么打。\n"
	b += "- 攻击链跑通后再写 finding：先把入口→前置→逐步利用真正走一遍、每步都有响应证据，再一次性落库；中途每得一个结论就 record_fact 先记下来，别攒到收尾（步数耗尽就全丢）。\n"
	return b
}
