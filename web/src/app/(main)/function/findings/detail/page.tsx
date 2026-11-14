"use client";

import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { ArrowLeftIcon, ArrowUpRightIcon, ShieldAlertIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { CopyButton } from "@/components/copy-button";
import { FindingRetestPanel } from "@/components/finding-retest-panel";
import { FindingTrafficPanel } from "@/components/finding-traffic-panel";
import { Markdown } from "@/components/markdown";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ApiError, api } from "@/lib/api";
import { statusMeta } from "@/lib/status";
import type {
  EnrichJob,
  Finding,
  FindingEvidenceEntry,
  FindingStatus,
  ReproStep,
  Reproduction,
  Severity,
} from "@/lib/types";

import { FindingLineageView } from "./lineage";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString("zh-CN");
}

// EvidenceCard 管理漏洞证据截图：上传（按步骤归属）/ 改图注 / 删除。
//
// 文件存服务器 evidence/<finding_id>/；取图走 cookie 鉴权（<img> 带不了 Authorization），
// 服务端固定图片 Content-Type + nosniff + inline —— 上传点不会变成 XSS 入口。
function EvidenceCard({ finding, onChanged }: { finding: Finding; onChanged: () => void }) {
  const id = finding.finding_id || finding.id;
  const [items, setItems] = React.useState<FindingEvidenceEntry[]>([]);
  const [step, setStep] = React.useState(0);
  const [busy, setBusy] = React.useState(false);
  const [editing, setEditing] = React.useState<number | null>(null);
  const [caption, setCaption] = React.useState("");

  const load = React.useCallback(() => {
    void api
      .evidence(id)
      .then(setItems)
      .catch((e) => toast.error(`读取截图失败：${(e as Error).message}`));
  }, [id]);
  React.useEffect(() => {
    load();
  }, [load]);

  async function upload(file: File) {
    setBusy(true);
    try {
      await api.uploadEvidence(id, file, { step_index: step });
      toast.success("已上传");
      load();
      onChanged();
    } catch (e) {
      toast.error(`上传失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  async function saveCaption(eid: number) {
    try {
      await api.updateEvidence(id, String(eid), { caption });
      setEditing(null);
      load();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    }
  }

  async function remove(eid: number) {
    if (!window.confirm("删除这张截图？文件会一并移除。")) return;
    try {
      await api.deleteEvidence(id, String(eid));
      load();
      onChanged();
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    }
  }

  const steps = finding.reproduction?.steps?.length ?? 0;

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="text-sm">证据截图</CardTitle>
        <div className="flex items-center gap-2">
          <select
            className="h-8 rounded-md border bg-transparent px-2 text-xs"
            value={step}
            onChange={(e) => setStep(Number(e.target.value))}
          >
            <option value={0}>总览（不归属步骤）</option>
            {Array.from({ length: steps }, (_, i) => (
              <option key={i + 1} value={i + 1}>
                步骤 {i + 1}
              </option>
            ))}
          </select>
          <label className="inline-flex">
            <input
              type="file"
              accept="image/png,image/jpeg,image/gif"
              className="hidden"
              disabled={busy}
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void upload(f);
                e.target.value = "";
              }}
            />
            <Button size="sm" variant="outline" asChild disabled={busy}>
              <span>上传截图</span>
            </Button>
          </label>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {items.length === 0 ? (
          <p className="text-muted-foreground text-sm">
            还没有截图。报告里图文对照最容易让客户确认问题真实存在。
          </p>
        ) : (
          items.map(({ evidence, url }) => (
            <div key={evidence.id} className="flex flex-col gap-1 rounded-md border p-2">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={url}
                alt={evidence.caption || evidence.filename}
                className="max-h-72 w-full rounded object-contain"
              />
              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0 flex-1">
                  {editing === evidence.id ? (
                    <div className="flex gap-1">
                      <Input className="h-7 text-xs" value={caption} onChange={(e) => setCaption(e.target.value)} />
                      <Button size="sm" variant="outline" onClick={() => saveCaption(evidence.id)}>
                        保存
                      </Button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      className="truncate text-left text-xs hover:underline"
                      onClick={() => {
                        setEditing(evidence.id);
                        setCaption(evidence.caption);
                      }}
                    >
                      {evidence.caption || "（无图注）"}
                    </button>
                  )}
                  <div className="text-muted-foreground text-[11px]">
                    {evidence.step_index > 0 ? `步骤 ${evidence.step_index}` : "总览"} · {evidence.width}×
                    {evidence.height} · {Math.round(evidence.bytes / 1024)} KB
                  </div>
                </div>
                <Button variant="ghost" size="icon" aria-label="删除" onClick={() => remove(evidence.id)}>
                  <Trash2Icon className="size-4" />
                </Button>
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}

// EnrichmentCard 展示 AI 富化的结构化交付字段（CVSS / 描述 / 影响 / 修复 / 复现步骤）。
//
// 复现步骤来自真实证据（agent 就地记录的 reproduction），不是模型复述 —— 所以这里
// 与报告里看到的内容完全一致。AI 只负责"改写散文"，这也是富化快而稳的原因。
function EnrichmentCard({ finding, onChanged }: { finding: Finding; onChanged: () => void }) {
  const id = finding.finding_id || finding.id;
  const [job, setJob] = React.useState<EnrichJob | null>(null);
  const [running, setRunning] = React.useState(false);

  const load = React.useCallback(() => {
    void api
      .getEnrichment(id)
      .then((r) => setJob({ status: r.enriched ? "done" : "idle", result: r.enrichment ?? undefined }))
      .catch(() => setJob({ status: "idle" }));
  }, [id]);
  React.useEffect(() => {
    load();
  }, [load]);

  // 轮询：analyzing 期间每 1.5s 取一次，直到 done/failed。
  React.useEffect(() => {
    if (job?.status !== "analyzing") return;
    const timer = window.setInterval(() => {
      void api.enrichStatus(id).then((j) => {
        setJob(j);
        if (j.status === "done") {
          setRunning(false);
          onChanged();
        }
        if (j.status === "failed") setRunning(false);
      });
    }, 1500);
    return () => window.clearInterval(timer);
  }, [job?.status, id, onChanged]);

  async function run() {
    setRunning(true);
    try {
      const j = await api.enrichFinding(id, document.documentElement.lang || "zh-CN");
      setJob(j);
    } catch (e) {
      setRunning(false);
      toast.error(`AI 分析失败：${(e as Error).message}`);
    }
  }

  const e = job?.result;

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="text-sm">AI 结构化分析</CardTitle>
        <Button size="sm" variant="outline" onClick={run} disabled={running || job?.status === "analyzing"}>
          {job?.status === "analyzing" ? "分析中…" : e ? "重新分析" : "AI 分析"}
        </Button>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {job?.status === "failed" && (
          <p className="rounded-md border border-destructive/40 bg-destructive/5 p-2 text-xs">
            分析失败：{job.error}
          </p>
        )}
        {!e && job?.status !== "analyzing" && job?.status !== "failed" && (
          <p className="text-muted-foreground text-sm">
            尚未做结构化分析。点「AI 分析」会生成 CVSS、描述、影响与修复建议（复现步骤由真实证据直接渲染）。
          </p>
        )}
        {e && (
          <>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              {e.cvss_score > 0 && (
                <Badge variant="secondary" className="font-mono">
                  CVSS {e.cvss_score.toFixed(1)}
                </Badge>
              )}
              {e.cvss_vector && (
                <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">{e.cvss_vector}</code>
              )}
              <Badge variant="outline">{e.source === "ai" ? "AI 生成" : "人工编辑"}</Badge>
              {e.module && <span className="text-muted-foreground">模块：{e.module}</span>}
              {e.target && <span className="text-muted-foreground">目标：{e.target}</span>}
            </div>
            {e.description.length > 0 && (
              <div className="text-sm leading-relaxed">
                {e.description.map((d, i) => (
                  <p key={i}>{d}</p>
                ))}
              </div>
            )}
            {e.risk_analysis.length > 0 && (
              <div>
                <div className="mb-1 font-medium text-xs">影响</div>
                <ul className="list-disc pl-5 text-sm">
                  {e.risk_analysis.map((d, i) => (
                    <li key={i}>{d}</li>
                  ))}
                </ul>
              </div>
            )}
            {e.remediation.length > 0 && (
              <div>
                <div className="mb-1 font-medium text-xs">修复建议</div>
                <ul className="list-disc pl-5 text-sm">
                  {e.remediation.map((d, i) => (
                    <li key={i}>{d}</li>
                  ))}
                </ul>
              </div>
            )}
            {e.test_process.length > 0 && (
              <div>
                <div className="mb-1 font-medium text-xs">复现步骤（真实证据）</div>
                {e.test_process.map((st, i) => (
                  <div key={i} className="mb-1 flex flex-col gap-1">
                    <div className="text-xs text-muted-foreground">步骤 {i + 1}{st.expected ? ` · ${st.expected}` : ""}</div>
                    {st.request && (
                      <pre className="max-h-40 overflow-auto rounded bg-muted px-2 py-1 font-mono text-[11px] whitespace-pre-wrap">
                        {st.request}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ReproductionCard 展示/编辑结构化复现过程：入口 → 前置 → 逐步（请求/响应/预期/证明）→ 来源。
// 报告按这个顺序逐段渲染成"步骤 1/2/3"，所以这里是唯一该改复现的地方 —— 让人从零复现，
// 而不是靠一段自由文本自己揣摩。
function ReproductionCard({ finding, onSaved }: { finding: Finding; onSaved: (f: Finding) => void }) {
  const [draft, setDraft] = React.useState<Reproduction>(finding.reproduction ?? {});
  const [saving, setSaving] = React.useState(false);
  const [editing, setEditing] = React.useState(false);

  React.useEffect(() => {
    setDraft(finding.reproduction ?? {});
    setEditing(false);
  }, [finding.id, finding.reproduction]);

  const steps = draft.steps ?? [];
  const hasContent =
    Boolean(draft.entry_point || draft.prerequisites || draft.provenance) || steps.length > 0;

  function patch(next: Partial<Reproduction>) {
    setDraft((cur) => ({ ...cur, ...next }));
  }
  function patchStep(i: number, next: Partial<ReproStep>) {
    const list = [...steps];
    list[i] = { ...list[i], ...next };
    patch({ steps: list });
  }

  async function save() {
    setSaving(true);
    try {
      const updated = await api.updateFinding(finding.finding_id || finding.id, { reproduction: draft });
      onSaved(updated);
      setEditing(false);
      toast.success("复现过程已保存");
    } catch (e) {
      toast.error("保存失败：" + (e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="text-sm">复现过程</CardTitle>
        <div className="flex gap-1">
          {editing ? (
            <>
              <Button size="sm" variant="ghost" onClick={() => { setDraft(finding.reproduction ?? {}); setEditing(false); }}>
                取消
              </Button>
              <Button size="sm" variant="outline" onClick={save} disabled={saving}>
                {saving ? "保存中…" : "保存"}
              </Button>
            </>
          ) : (
            <Button size="sm" variant="outline" disabled={finding.inherited} onClick={() => setEditing(true)}>
              编辑
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {!hasContent && !editing && (
          <p className="text-muted-foreground text-sm">
            尚未登记结构化复现过程。报告里这条漏洞只会显示"未登记"，工程师得自己猜怎么打。
          </p>
        )}

        {!editing ? (
          <>
            {draft.entry_point && (
              <FieldRow label="入口点">
                <code className="font-mono text-xs">{draft.entry_point}</code>
              </FieldRow>
            )}
            {draft.prerequisites && (
              <div className="text-sm">
                <span className="text-muted-foreground">前置条件：</span>
                <span className="whitespace-pre-wrap">{draft.prerequisites}</span>
              </div>
            )}
            {steps.map((st, i) => (
              <div key={i} className="flex flex-col gap-1 border-t pt-2 first:border-0 first:pt-0">
                <div className="font-medium text-xs">步骤 {i + 1}</div>
                {st.expected && <p className="text-xs text-muted-foreground">预期：{st.expected}</p>}
                {st.request && (
                  <pre className="max-h-40 overflow-auto rounded bg-muted px-2 py-1 font-mono text-[11px] whitespace-pre-wrap">
                    {st.request}
                  </pre>
                )}
                {st.response && (
                  <pre className="max-h-40 overflow-auto rounded bg-muted px-2 py-1 font-mono text-[11px] whitespace-pre-wrap">
                    {st.response}
                  </pre>
                )}
                {st.proves && <p className="text-xs">{st.proves}</p>}
              </div>
            ))}
            {draft.provenance && (
              <p className="text-xs text-muted-foreground">攻击链来源：{draft.provenance}</p>
            )}
          </>
        ) : (
          <>
            <div className="grid gap-2 sm:grid-cols-2">
              <div className="grid gap-1">
                <Label className="text-xs text-muted-foreground">入口点</Label>
                <Input
                  value={draft.entry_point ?? ""}
                  placeholder="POST /api/login"
                  onChange={(e) => patch({ entry_point: e.target.value })}
                />
              </div>
              <div className="grid gap-1">
                <Label className="text-xs text-muted-foreground">攻击链来源</Label>
                <Input
                  value={draft.provenance ?? ""}
                  placeholder="从事实 #12 的报错指纹推来"
                  onChange={(e) => patch({ provenance: e.target.value })}
                />
              </div>
            </div>
            <div className="grid gap-1">
              <Label className="text-xs text-muted-foreground">前置条件（含账号如何获得）</Label>
              <Textarea
                rows={2}
                value={draft.prerequisites ?? ""}
                placeholder="需要普通用户账号，通过 /register 自助注册"
                onChange={(e) => patch({ prerequisites: e.target.value })}
              />
            </div>
            {steps.map((st, i) => (
              <div key={i} className="flex flex-col gap-2 rounded-md border p-2">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-xs">步骤 {i + 1}</span>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label="删除该步骤"
                    onClick={() => patch({ steps: steps.filter((_, j) => j !== i) })}
                  >
                    <Trash2Icon className="size-4" />
                  </Button>
                </div>
                <Textarea
                  rows={2}
                  className="font-mono text-xs"
                  placeholder="真实请求原文（逐字）"
                  value={st.request ?? ""}
                  onChange={(e) => patchStep(i, { request: e.target.value })}
                />
                <Textarea
                  rows={2}
                  className="font-mono text-xs"
                  placeholder="真实响应关键片段（逐字）"
                  value={st.response ?? ""}
                  onChange={(e) => patchStep(i, { response: e.target.value })}
                />
                <div className="grid gap-2 sm:grid-cols-2">
                  <Input
                    placeholder="预期"
                    value={st.expected ?? ""}
                    onChange={(e) => patchStep(i, { expected: e.target.value })}
                  />
                  <Input
                    placeholder="这一步证明了什么"
                    value={st.proves ?? ""}
                    onChange={(e) => patchStep(i, { proves: e.target.value })}
                  />
                </div>
              </div>
            ))}
            <Button
              size="sm"
              variant="outline"
              onClick={() => patch({ steps: [...steps, { request: "", response: "", expected: "", proves: "" }] })}
            >
              添加步骤
            </Button>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ReportFieldsCard 编辑交付级报告字段（CVSS / 影响 / 修复建议）。
// 报告渲染只读这三项 + 摘要证据，不调 LLM —— 所以在详情页改完，下次生成的 .docx
// 里就是改后的内容，可离线复现、可逐条复核。
function ReportFieldsCard({ finding, onSaved }: { finding: Finding; onSaved: (f: Finding) => void }) {
  const [cvss, setCvss] = React.useState(finding.cvss ?? "");
  const [impact, setImpact] = React.useState(finding.impact ?? "");
  const [remediation, setRemediation] = React.useState(finding.remediation ?? "");
  const [saving, setSaving] = React.useState(false);

  // 切换漏洞时重置草稿（组件按 id 复用，不能把上一个漏洞的值带过来）
  React.useEffect(() => {
    setCvss(finding.cvss ?? "");
    setImpact(finding.impact ?? "");
    setRemediation(finding.remediation ?? "");
  }, [finding.id, finding.cvss, finding.impact, finding.remediation]);

  const dirty =
    cvss !== (finding.cvss ?? "") || impact !== (finding.impact ?? "") || remediation !== (finding.remediation ?? "");

  async function save() {
    setSaving(true);
    try {
      const updated = await api.updateFinding(finding.finding_id || finding.id, { cvss, impact, remediation });
      onSaved(updated);
      toast.success("报告字段已保存");
    } catch (e) {
      toast.error("保存失败：" + (e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="text-sm">报告字段</CardTitle>
        <Button size="sm" variant="outline" onClick={save} disabled={saving || !dirty || finding.inherited}>
          {saving ? "保存中…" : "保存"}
        </Button>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <p className="text-muted-foreground text-xs">
          这些字段直接进入交付报告的属性表；报告渲染不调用模型，改完即生效。
        </p>
        <div className="grid gap-3 sm:grid-cols-[140px_1fr]">
          <div className="grid gap-1">
            <Label className="text-xs text-muted-foreground">CVSS</Label>
            <Input
              value={cvss}
              placeholder="如 9.8 或 AV:N/AC:L/…"
              disabled={finding.inherited}
              onChange={(e) => setCvss(e.target.value)}
            />
          </div>
          <div className="grid gap-1">
            <Label className="text-xs text-muted-foreground">影响</Label>
            <Input
              value={impact}
              placeholder="如 可读取全库用户数据"
              disabled={finding.inherited}
              onChange={(e) => setImpact(e.target.value)}
            />
          </div>
        </div>
        <div className="grid gap-1">
          <Label className="text-xs text-muted-foreground">修复建议</Label>
          <Textarea
            value={remediation}
            rows={3}
            placeholder="如 改用参数化查询，并给数据库账号最小权限"
            disabled={finding.inherited}
            onChange={(e) => setRemediation(e.target.value)}
          />
        </div>
      </CardContent>
    </Card>
  );
}

// FieldRow is one label/value line in the right-hand status panel.
function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5">
      <span className="shrink-0 pt-0.5 text-xs text-muted-foreground">{label}</span>
      <div className="flex min-w-0 flex-col items-end gap-1 text-right text-sm">{children}</div>
    </div>
  );
}

function FindingDetailInner() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const contextTaskId = searchParams.get("context_task") ?? "";
  const [finding, setFinding] = React.useState<Finding | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [notFound, setNotFound] = React.useState(false);
  const [tab, setTab] = React.useState("overview");

  const load = React.useCallback(() => {
    if (!id) {
      setLoaded(true);
      return;
    }
    setLoaded(false);
    setLoadError(null);
    api
      .getFinding(id, contextTaskId || undefined)
      .then((f) => {
        setFinding(f);
        setLoadError(null);
      })
      .catch((e: unknown) => {
        // Only a 404 means the finding is really gone. A 5xx or a dropped
        // connection during a backend restart needs an error + retry, not a
        // "未找到" page that asserts the record was deleted.
        setFinding(null);
        setNotFound(e instanceof ApiError && e.status === 404);
        setLoadError(e instanceof Error ? e.message : "加载失败");
      })
      .finally(() => setLoaded(true));
  }, [contextTaskId, id]);
  React.useEffect(() => {
    load();
  }, [load]);

  const changeSeverity = React.useCallback(
    async (next: Severity) => {
      if (!finding || finding.inherited || next === finding.severity) return;
      const prev = finding.severity;
      setFinding({ ...finding, severity: next });
      try {
        const updated = await api.setFindingSeverity(id, next);
        setFinding(updated);
        toast.success(`严重等级已改为「${statusMeta("severity", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, severity: prev } : cur));
        toast.error("更新失败：" + (e as Error).message);
      }
    },
    [finding, id],
  );

  const changeStatus = React.useCallback(
    async (next: FindingStatus) => {
      if (!finding || finding.inherited || next === finding.status) return;
      const prev = finding.status;
      setFinding({ ...finding, status: next });
      try {
        const updated = await api.setFindingStatus(id, next);
        setFinding(updated);
        toast.success(`处理状态已改为「${statusMeta("finding", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, status: prev } : cur));
        toast.error("更新失败：" + (e as Error).message);
      }
    },
    [finding, id],
  );

  if (!finding) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
        <p className="text-muted-foreground">
          {!loaded ? "加载中…" : loadError && !notFound ? `加载失败：${loadError}` : `未找到发现 ${id}`}
        </p>
        {loaded && loadError && !notFound && (
          <Button variant="outline" onClick={() => load()}>
            重试
          </Button>
        )}
        {loaded && (!loadError || notFound) && (
          <Button asChild variant="outline">
            <Link href="/function/findings">
              <ArrowLeftIcon /> 返回发现列表
            </Link>
          </Button>
        )}
      </div>
    );
  }

  const title = finding.name || finding.vulnclass || "未分类";

  return (
    <Tabs value={tab} onValueChange={setTab} className="flex flex-1 flex-col gap-0">
      {/* Sticky header */}
      <header className="sticky top-0 z-10 flex flex-col gap-2 border-b bg-background/95 px-4 py-2.5 backdrop-blur lg:px-6">
        <div className="flex flex-wrap items-center gap-2">
          <SidebarTrigger className="-ml-1" />
          <Button asChild variant="ghost" size="icon" className="size-7">
            <Link href="/function/findings">
              <ArrowLeftIcon />
            </Link>
          </Button>
          <ShieldAlertIcon className="size-4 text-muted-foreground" />
          <h1 className="max-w-md truncate text-sm font-semibold" title={title}>
            {title}
          </h1>
          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">#{finding.id}</code>
          <Separator orientation="vertical" className="mx-1 h-4" />
          <StatusBadge domain="severity" value={finding.severity} dot />
          <StatusBadge domain="finding" value={finding.status} dot />
          {finding.inherited && finding.source_task_id && (
            <Badge variant="outline">来源任务 #{finding.source_task_id} · 只读</Badge>
          )}
        </div>
        <TabsList>
          <TabsTrigger value="overview">概览</TabsTrigger>
          <TabsTrigger value="lineage">链路图</TabsTrigger>
        </TabsList>
      </header>

      {/* Tab content */}
      <div className="flex-1 p-4 lg:p-6">
        {/* 概览：左（摘要 + 证据）/ 右（状态区） */}
        <TabsContent value="overview" className="mt-0">
          <div className="grid gap-4 lg:grid-cols-3">
            {/* 左栏 */}
            <div className="flex flex-col gap-4 lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">摘要</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm leading-relaxed whitespace-pre-wrap">{finding.summary || "（无摘要）"}</p>
                </CardContent>
              </Card>
              <EnrichmentCard finding={finding} onChanged={load} />
              <EvidenceCard finding={finding} onChanged={load} />
              <ReportFieldsCard finding={finding} onSaved={setFinding} />
              <ReproductionCard finding={finding} onSaved={setFinding} />
              <FindingRetestPanel key={id} findingId={id} readOnly={finding.inherited} onCompleted={load} />
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">证据 / PoC</CardTitle>
                </CardHeader>
                <CardContent>
                  {finding.evidence ? (
                    <pre className="max-h-[46vh] overflow-auto rounded-md bg-muted px-3 py-2 font-mono text-xs whitespace-pre-wrap">
                      {finding.evidence}
                    </pre>
                  ) : (
                    <p className="text-sm text-muted-foreground">（无证据）</p>
                  )}
                </CardContent>
              </Card>
              <FindingTrafficPanel
                key={id}
                findingId={id}
                contextTask={contextTaskId || undefined}
                readOnly={finding.inherited}
                onChanged={load}
              />
              {/* 证据下方：详细报告(Markdown 渲染) */}
              <Card>
                <CardHeader className="flex-row items-center justify-between">
                  <CardTitle className="text-sm">详细报告</CardTitle>
                  {finding.report && <CopyButton text={finding.report} successMessage="已复制详细报告" />}
                </CardHeader>
                <CardContent>
                  {finding.report_stale ? (
                    <Alert>
                      <AlertDescription>流量证据已变更，详细报告待更新。</AlertDescription>
                    </Alert>
                  ) : null}
                  {finding.report ? (
                    <Markdown text={finding.report} />
                  ) : (
                    <p className="text-sm text-muted-foreground">暂无详细报告。</p>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* 右栏：状态区 */}
            <Card className="h-fit lg:sticky lg:top-24">
              <CardHeader>
                <CardTitle className="text-sm">状态</CardTitle>
              </CardHeader>
              <CardContent className="divide-y">
                {/* 漏洞 ID */}
                <FieldRow label="漏洞 ID">
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                    #{finding.id}
                  </code>
                </FieldRow>

                {/* 严重等级 */}
                <FieldRow label="严重等级">
                  {finding.inherited ? (
                    <StatusBadge domain="severity" value={finding.severity} dot />
                  ) : (
                    <Select value={finding.severity} onValueChange={(v) => changeSeverity(v as Severity)}>
                      <SelectTrigger size="sm" className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0">
                        <StatusBadge domain="severity" value={finding.severity} dot />
                      </SelectTrigger>
                      <SelectContent position="popper" align="end">
                        <SelectGroup>
                          {SEVERITIES.map((sv) => (
                            <SelectItem key={sv} value={sv}>
                              {statusMeta("severity", sv).label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  )}
                </FieldRow>

                {/* 处理状态 */}
                <FieldRow label="处理状态">
                  {finding.inherited ? (
                    <StatusBadge domain="finding" value={finding.status} dot />
                  ) : (
                    <Select value={finding.status} onValueChange={(v) => changeStatus(v as FindingStatus)}>
                      <SelectTrigger size="sm" className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0">
                        <StatusBadge domain="finding" value={finding.status} dot />
                      </SelectTrigger>
                      <SelectContent position="popper" align="end">
                        <SelectGroup>
                          {FINDING_STATUSES.map((st) => (
                            <SelectItem key={st} value={st}>
                              {statusMeta("finding", st).label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  )}
                </FieldRow>

                {/* 漏洞类型 */}
                <FieldRow label="漏洞类型">
                  {finding.vulnclass ? (
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{finding.vulnclass}</code>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </FieldRow>

                {/* 涉及资产 */}
                <FieldRow label="涉及资产">
                  {finding.assets && finding.assets.length > 0 ? (
                    <div className="flex flex-wrap justify-end gap-1">
                      {finding.assets.map((a) => (
                        <code
                          key={a.id}
                          className="max-w-[16rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                          title={`${a.type} · ${a.label}`}
                        >
                          {a.label}
                        </code>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </FieldRow>

                {/* 所属任务 */}
                <FieldRow label="所属任务">
                  {finding.task_id ? (
                    <Link
                      href={`/function/tasks/detail?id=${finding.task_id}`}
                      className="inline-flex max-w-[16rem] items-center gap-1 text-primary hover:underline"
                      title={finding.task_description}
                    >
                      <span className="truncate">{finding.task_description || `#${finding.task_id}`}</span>
                      <ArrowUpRightIcon className="size-3 shrink-0" />
                    </Link>
                  ) : (
                    <span className="text-muted-foreground">—（任务已删除）</span>
                  )}
                </FieldRow>

                {/* 发现时间 */}
                <FieldRow label="发现时间">
                  <span className="tabular-nums">{fmtTime(finding.ts)}</span>
                </FieldRow>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 链路图：从任务初始节点回溯到本漏洞节点的攻击链路 */}
        <TabsContent value="lineage" className="mt-0">
          <FindingLineageView findingId={finding.id} />
        </TabsContent>
      </div>
    </Tabs>
  );
}

// useSearchParams must sit under a Suspense boundary for static export.
export default function FindingDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <FindingDetailInner />
    </React.Suspense>
  );
}
