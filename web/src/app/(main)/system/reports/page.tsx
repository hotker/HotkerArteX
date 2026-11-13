"use client";

import { Download, FileText, Settings2, Trash2 } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { ReportPerson, ReportRecord, ReportSettings } from "@/lib/types";

// 交付级报告页：组织级设置 + 按任务生成 .docx + 历史下载。
//
// 设计取舍：生成是【同步】的。docx 由纯 Go 渲染（没有 python 子进程、没有 LLM 调用），
// 毫秒级返回，所以直接把"文件大小 / 漏洞数 / 下载按钮"给出来，比异步队列 + 轮询
// 更容易判断失败原因。

const LANGS = [
  { value: "zh-CN", label: "简体中文" },
  { value: "zh-TW", label: "繁體中文" },
  { value: "en-US", label: "English" },
] as const;

const emptySettings: ReportSettings = {
  configured: false,
  company: "",
  client: "",
  confidential: "密级：机密",
  lang: "zh-CN",
  version: "v1.0",
  people: [],
};

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function fmtTime(s: string): string {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleString();
}

export default function ReportsPage() {
  const [settings, setSettings] = React.useState<ReportSettings>(emptySettings);
  const [saving, setSaving] = React.useState(false);
  const [reports, setReports] = React.useState<ReportRecord[]>([]);
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(async () => {
    try {
      const [st, list] = await Promise.all([api.reportSettings(), api.reports()]);
      setSettings({ ...emptySettings, ...st });
      setReports(list);
    } catch (e) {
      toast.error(`加载失败：${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function save() {
    setSaving(true);
    try {
      const { configured: _c, updated_at: _u, ...payload } = settings;
      await api.saveReportSettings(payload);
      toast.success("报告设置已保存");
      await load();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function remove(r: ReportRecord) {
    if (!window.confirm(`删除报告「${r.file_name}」？文件会一并从磁盘移除。`)) return;
    try {
      await api.deleteReport(String(r.id));
      toast.success("已删除");
      await load();
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    }
  }

  function setPerson(i: number, patch: Partial<ReportPerson>) {
    setSettings((prev) => {
      const people = [...prev.people];
      people[i] = { ...people[i], ...patch };
      return { ...prev, people };
    });
  }

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl">报告交付</h1>
          <p className="text-muted-foreground text-sm">
            按任务生成人工级 .docx（封面 / 目录 / 页码 / 每漏洞属性表与复现步骤）。正文只取库里已确认的事实，
            同一份数据任何时候生成结果一致。
          </p>
        </div>
        {!settings.configured && <Badge variant="outline">尚未配置出具方</Badge>}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Settings2 className="size-4" /> 组织级设置
          </CardTitle>
          <CardDescription>封面信息与署名人员；配置一次，所有报告复用。</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <Field label="出具方" value={settings.company} onChange={(v) => setSettings({ ...settings, company: v })} placeholder="如 XX 安全" />
            <Field label="客户" value={settings.client} onChange={(v) => setSettings({ ...settings, client: v })} placeholder="如 示例客户" />
            <Field
              label="密级"
              value={settings.confidential}
              onChange={(v) => setSettings({ ...settings, confidential: v })}
              placeholder="如 密级：机密"
            />
            <Field label="版本" value={settings.version} onChange={(v) => setSettings({ ...settings, version: v })} placeholder="v1.0" />
            <div className="grid gap-2">
              <Label className="text-sm">默认语言</Label>
              <Select value={settings.lang} onValueChange={(v) => setSettings({ ...settings, lang: v })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {LANGS.map((l) => (
                    <SelectItem key={l.value} value={l.value}>
                      {l.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <Label className="text-sm">署名人员</Label>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setSettings({ ...settings, people: [...settings.people, { name: "", role: "", contact: "" }] })}
              >
                添加一行
              </Button>
            </div>
            {settings.people.length === 0 && (
              <p className="text-muted-foreground text-xs">未填写时，报告的「测试人员」行不会出现。</p>
            )}
            {settings.people.map((p, i) => (
              <div key={i} className="grid gap-2 sm:grid-cols-[1fr_1fr_1fr_auto]">
                <Input placeholder="姓名" value={p.name} onChange={(e) => setPerson(i, { name: e.target.value })} />
                <Input placeholder="角色（主测 / 复核）" value={p.role} onChange={(e) => setPerson(i, { role: e.target.value })} />
                <Input placeholder="联系方式" value={p.contact} onChange={(e) => setPerson(i, { contact: e.target.value })} />
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label="删除该行"
                  onClick={() => setSettings({ ...settings, people: settings.people.filter((_, j) => j !== i) })}
                >
                  <Trash2 className="size-4" />
                </Button>
              </div>
            ))}
          </div>

          <div>
            <Button onClick={save} disabled={saving}>
              {saving ? "保存中…" : "保存设置"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileText className="size-4" /> 已生成报告
          </CardTitle>
          <CardDescription>文件存放在服务器数据目录 reports/ 下；删除记录即删除文件。</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="mb-3 flex justify-end">
            <GenerateDialog onDone={load} defaultLang={settings.lang} configured={settings.configured} />
          </div>
          {loading ? (
            <p className="text-muted-foreground text-sm">加载中…</p>
          ) : reports.length === 0 ? (
            <p className="text-muted-foreground text-sm">还没有报告。选一个任务，点「生成报告」。</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>文件名</TableHead>
                  <TableHead>任务</TableHead>
                  <TableHead>语言</TableHead>
                  <TableHead className="text-right">漏洞数</TableHead>
                  <TableHead className="text-right">大小</TableHead>
                  <TableHead>生成时间</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="max-w-[280px] truncate font-mono text-xs" title={r.file_name}>
                      {r.file_name}
                    </TableCell>
                    <TableCell className="text-xs">
                      {r.task_id ? `#${r.task_id}` : "—"}
                    </TableCell>
                    <TableCell className="text-xs">{r.lang}</TableCell>
                    <TableCell className="text-right text-xs">{r.findings_count}</TableCell>
                    <TableCell className="text-right text-xs">{fmtSize(r.size_bytes)}</TableCell>
                    <TableCell className="text-xs">{fmtTime(r.created_at)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button asChild size="sm" variant="outline">
                          <a href={api.reportDownloadURL(String(r.id))} download>
                            <Download className="size-3.5" /> 下载
                          </a>
                        </Button>
                        <Button variant="ghost" size="icon" aria-label="删除报告" onClick={() => void remove(r)}>
                          <Trash2 className="size-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <div className="grid gap-2">
      <Label className="text-sm">{label}</Label>
      <Input value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}

// GenerateDialog 选任务 + 语言 → 同步生成并立刻给下载入口。
function GenerateDialog({
  onDone,
  defaultLang,
  configured,
}: {
  onDone: () => void | Promise<void>;
  defaultLang: string;
  configured: boolean;
}) {
  const [open, setOpen] = React.useState(false);
  const [tasks, setTasks] = React.useState<{ id: string; label: string }[]>([]);
  const [taskID, setTaskID] = React.useState("");
  const [title, setTitle] = React.useState("");
  const [lang, setLang] = React.useState(defaultLang || "zh-CN");
  const [busy, setBusy] = React.useState(false);
  const [made, setMade] = React.useState<ReportRecord | null>(null);

  React.useEffect(() => {
    if (!open) return;
    setLang(defaultLang || "zh-CN");
    setMade(null);
    void (async () => {
      try {
        const { tasks: list } = await api.tasks();
        setTasks(
          list.map((t) => ({
            id: String(t.id),
            label: `#${t.id} ${t.name || t.description || "未命名任务"}`,
          })),
        );
        if (list.length > 0) setTaskID(String(list[0].id));
      } catch (e) {
        toast.error(`读取任务失败：${(e as Error).message}`);
      }
    })();
  }, [open, defaultLang]);

  async function generate() {
    if (!taskID) {
      toast.error("先选一个任务");
      return;
    }
    setBusy(true);
    try {
      const rec = await api.generateReport({ task_id: taskID, title: title.trim() || undefined, lang });
      setMade(rec);
      toast.success(`已生成：${rec.file_name}（${rec.findings_count} 个漏洞）`);
      await onDone();
    } catch (e) {
      toast.error(`生成失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">生成报告</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>生成报告</DialogTitle>
          <DialogDescription>
            选任务与语言，正文取该任务已确认的漏洞（含复现步骤、关联流量与资产范围）。
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 py-2">
          {!configured && (
            <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs">
              还没配置出具方/客户 —— 报告封面会留空。建议先在上面「组织级设置」里填好再生成。
            </p>
          )}
          <div className="grid gap-2">
            <Label className="text-sm">任务</Label>
            <Select value={taskID} onValueChange={setTaskID}>
              <SelectTrigger>
                <SelectValue placeholder="选择任务" />
              </SelectTrigger>
              <SelectContent>
                {tasks.map((t) => (
                  <SelectItem key={t.id} value={t.id}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-2">
            <Label className="text-sm">报告标题（可选）</Label>
            <Input value={title} placeholder="留空 = 用任务名" onChange={(e) => setTitle(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label className="text-sm">语言</Label>
            <Select value={lang} onValueChange={setLang}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LANGS.map((l) => (
                  <SelectItem key={l.value} value={l.value}>
                    {l.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {made && (
            <div className="flex items-center justify-between rounded-md border p-2 text-sm">
              <span className="truncate font-mono text-xs">{made.file_name}</span>
              <Button asChild size="sm" variant="outline">
                <a href={api.reportDownloadURL(String(made.id))} download>
                  <Download className="size-3.5" /> 下载
                </a>
              </Button>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            关闭
          </Button>
          <Button onClick={generate} disabled={busy}>
            {busy ? "生成中…" : "生成"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}