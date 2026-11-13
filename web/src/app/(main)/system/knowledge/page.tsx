"use client";

import { DatabaseIcon, RefreshCwIcon, SearchIcon, Trash2Icon, UploadIcon } from "lucide-react";
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
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { KnowledgeConfig, KnowledgeDoc, KnowledgeHit, KnowledgeRetrievalLog } from "@/lib/types";

// 知识库页：文档管理（全局/任务） + Embedder 配置 + 试检索 + 检索审计。
//
// 语义检索不是"要么能用要么不能用"：pgvector 或 embedder 缺一个就整体降级为关键词检索，
// 页面顶部如实显示当前模式 —— 用户据此判断"召回不准"是配置问题还是内容问题。

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtTime(s: string): string {
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toLocaleString();
}

export default function KnowledgePage() {
  const [docs, setDocs] = React.useState<KnowledgeDoc[]>([]);
  const [meta, setMeta] = React.useState({ global: 0, task: 0, vectorReady: false, semantic: false });
  const [scope, setScope] = React.useState<"all" | "global" | "task">("all");
  const [loading, setLoading] = React.useState(true);
  const [cfg, setCfg] = React.useState<KnowledgeConfig | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [list, conf] = await Promise.all([
        api.knowledgeDocs(scope === "all" ? {} : { scope }),
        api.knowledgeConfig(),
      ]);
      setDocs(list.docs);
      setMeta({
        global: list.global_count,
        task: list.task_count,
        vectorReady: list.vector_ready,
        semantic: list.semantic,
      });
      setCfg(conf);
    } catch (e) {
      toast.error(`加载失败：${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, [scope]);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function remove(doc: KnowledgeDoc) {
    if (!window.confirm(`删除知识「${doc.title}」？其向量分块会一并删除。`)) return;
    try {
      await api.deleteKnowledgeDoc(String(doc.id));
      toast.success("已删除");
      await load();
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    }
  }

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl">知识库</h1>
          <p className="text-muted-foreground text-sm">
            两层 RAG：全局库（方法论 / 漏洞库 / 技巧）+ 任务库（授权范围 / 评分规则 / 目标）。
            Agent 通过 <code className="font-mono text-xs">search_knowledge</code> 在动手前检索。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={meta.semantic ? "default" : "secondary"}>
            {meta.semantic ? "语义检索" : "关键词检索"}
          </Badge>
          {!meta.vectorReady && <Badge variant="outline">pgvector 未启用</Badge>}
          <Badge variant="outline">全局 {meta.global}</Badge>
          <Badge variant="outline">任务 {meta.task}</Badge>
        </div>
      </div>

      {!meta.semantic && (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs">
          {meta.vectorReady
            ? "语义检索未启用：到下方「Embedder 配置」打开开关并填 API Key，再点「重建索引」。"
            : "语义检索不可用：数据库未安装 pgvector（需超级用户执行一次 CREATE EXTENSION vector）。当前按关键词检索，功能不受影响。"}
        </p>
      )}

      <Tabs defaultValue="docs">
        <TabsList>
          <TabsTrigger value="docs">文档</TabsTrigger>
          <TabsTrigger value="embedder">Embedder 配置</TabsTrigger>
          <TabsTrigger value="search">试检索</TabsTrigger>
          <TabsTrigger value="logs">检索审计</TabsTrigger>
        </TabsList>

        <TabsContent value="docs" className="mt-4">
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2 text-base">
                  <DatabaseIcon className="size-4" /> 知识文档
                </CardTitle>
                <CardDescription>支持 .md/.txt/.csv/.json/.docx/.html（PDF 请先导出为文本）。</CardDescription>
              </div>
              <div className="flex items-center gap-2">
                <select
                  className="h-9 rounded-md border bg-transparent px-2 text-sm"
                  value={scope}
                  onChange={(e) => setScope(e.target.value as "all" | "global" | "task")}
                >
                  <option value="all">全部</option>
                  <option value="global">仅全局</option>
                  <option value="task">仅任务</option>
                </select>
                <UploadDialog onDone={load} />
                <NewDocDialog onDone={load} />
              </div>
            </CardHeader>
            <CardContent>
              {loading ? (
                <p className="text-muted-foreground text-sm">加载中…</p>
              ) : docs.length === 0 ? (
                <p className="text-muted-foreground text-sm">还没有知识文档。上传一份方法论或任务资料开始。</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>标题</TableHead>
                      <TableHead>范围</TableHead>
                      <TableHead>分类</TableHead>
                      <TableHead>来源</TableHead>
                      <TableHead className="text-right">大小</TableHead>
                      <TableHead className="text-right">分块</TableHead>
                      <TableHead>索引</TableHead>
                      <TableHead className="text-right">操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {docs.map((d) => (
                      <TableRow key={d.id}>
                        <TableCell className="max-w-[320px] truncate" title={d.title}>
                          {d.title}
                        </TableCell>
                        <TableCell className="text-xs">
                          {d.scope === "task" ? `任务 #${d.task_id ?? "?"}` : "全局"}
                        </TableCell>
                        <TableCell className="text-xs">{d.category || "—"}</TableCell>
                        <TableCell className="text-xs">{d.source}</TableCell>
                        <TableCell className="text-right text-xs">{fmtBytes(d.bytes)}</TableCell>
                        <TableCell className="text-right text-xs">{d.chunks}</TableCell>
                        <TableCell>
                          <Badge variant={d.indexed ? "secondary" : "outline"}>{d.indexed ? "已索引" : "未索引"}</Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button variant="ghost" size="icon" aria-label="删除" onClick={() => void remove(d)}>
                            <Trash2Icon className="size-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="embedder" className="mt-4">
          {cfg && <EmbedderCard cfg={cfg} onSaved={load} />}
        </TabsContent>

        <TabsContent value="search" className="mt-4">
          <SearchCard semantic={meta.semantic} />
        </TabsContent>

        <TabsContent value="logs" className="mt-4">
          <LogsCard />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ---------------- Embedder 配置 ----------------

function EmbedderCard({ cfg, onSaved }: { cfg: KnowledgeConfig; onSaved: () => Promise<void> }) {
  const [open, setOpen] = React.useState(false);
  const [enabled, setEnabled] = React.useState(cfg.enabled);
  const [baseURL, setBaseURL] = React.useState(cfg.base_url);
  const [model, setModel] = React.useState(cfg.model);
  const [dim, setDim] = React.useState(String(cfg.dim));
  const [apiKey, setApiKey] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    setEnabled(cfg.enabled);
    setBaseURL(cfg.base_url);
    setModel(cfg.model);
    setDim(String(cfg.dim));
  }, [cfg]);

  async function save() {
    setBusy(true);
    try {
      const r = await api.saveKnowledgeConfig({
        enabled,
        base_url: baseURL.trim(),
        model: model.trim(),
        dim: Number(dim) || 1024,
        api_key: apiKey.trim() || undefined,
      });
      toast.success(r.semantic ? "已保存，语义检索已就绪（记得重建索引）" : "已保存（语义检索尚未就绪）");
      setApiKey("");
      await onSaved();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  async function test() {
    setBusy(true);
    try {
      const r = await api.testKnowledgeEmbedder();
      if (r.ok) toast.success(`连通成功，返回维度 ${r.dim}`);
      else toast.error(`连通失败：${r.error ?? "未知错误"}`);
    } catch (e) {
      toast.error(`测试失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  async function reindex() {
    if (!window.confirm("重建索引会重新向量化全部文档，配置错时可能耗时较久。继续？")) return;
    setBusy(true);
    try {
      const r = await api.reindexKnowledge();
      if (r.ok) toast.success(`已重建 ${r.indexed} 篇文档的索引`);
      else toast.error(`重建失败：${r.error ?? "未知错误"}`);
      await onSaved();
    } catch (e) {
      toast.error(`重建失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Embedder 配置</CardTitle>
        <CardDescription>
          OpenAI 兼容 embeddings 端点（智谱 / 硅基流动 / OpenAI / Ollama）。不配置则用关键词检索。
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex items-center justify-between gap-4 rounded-md border p-3">
          <div className="grid gap-0.5">
            <Label className="text-sm">启用语义检索</Label>
            <p className="text-muted-foreground text-xs">
              {cfg.vector_ready ? (cfg.has_key ? "已配置 API Key" : "未配置 API Key") : "pgvector 未启用，打开也不生效"}
            </p>
          </div>
          <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="启用语义检索" />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label className="text-sm">端点 Base URL</Label>
            <Input
              className="font-mono"
              value={baseURL}
              placeholder="https://open.bigmodel.cn/api/paas/v4"
              onChange={(e) => setBaseURL(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label className="text-sm">模型</Label>
            <Input className="font-mono" value={model} placeholder="embedding-3" onChange={(e) => setModel(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label className="text-sm">维度</Label>
            <Input
              type="number"
              value={dim}
              min={64}
              max={4096}
              onChange={(e) => setDim(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label className="text-sm">API Key</Label>
            <Input
              type="password"
              value={apiKey}
              placeholder={cfg.has_key ? "留空保留现有" : "sk-…"}
              onChange={(e) => setApiKey(e.target.value)}
            />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button onClick={save} disabled={busy}>
            {busy ? "处理中…" : "保存"}
          </Button>
          <Button variant="outline" onClick={test} disabled={busy}>
            测试连通
          </Button>
          <Button variant="outline" onClick={reindex} disabled={busy}>
            <RefreshCwIcon className="size-4" /> 重建索引
          </Button>
        </div>
        <p className="text-muted-foreground text-xs">
          换模型或维度后必须重建索引：检索只比较同一模型的向量，旧向量会被忽略（这是换模型不串味的安全阀）。
        </p>
      </CardContent>
    </Card>
  );
}

// ---------------- 试检索 ----------------

function SearchCard({ semantic }: { semantic: boolean }) {
  const [query, setQuery] = React.useState("");
  const [hits, setHits] = React.useState<KnowledgeHit[]>([]);
  const [mode, setMode] = React.useState<string>("");
  const [busy, setBusy] = React.useState(false);

  async function run() {
    if (!query.trim()) return;
    setBusy(true);
    try {
      const r = await api.searchKnowledge({ query: query.trim(), top_k: 5 });
      setHits(r.hits);
      setMode(r.mode);
      if (r.hits.length === 0) toast.info("没有命中");
    } catch (e) {
      toast.error(`检索失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">试检索</CardTitle>
        <CardDescription>用自然语言描述你要找什么。当前模式：{semantic ? "语义" : "关键词"}。</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex gap-2">
          <Input
            value={query}
            placeholder="例如：文件上传绕过的常见手法"
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void run();
            }}
          />
          <Button onClick={run} disabled={busy}>
            <SearchIcon className="size-4" /> 检索
          </Button>
        </div>
        {mode && <p className="text-muted-foreground text-xs">本次使用：{mode}</p>}
        {hits.map((h, i) => (
          <div key={`${h.doc_id}-${i}`} className="flex flex-col gap-1 rounded-md border p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium text-sm">{h.title}</span>
              <Badge variant="outline" className="text-xs">
                {(h.score * 100).toFixed(0)}% · {h.scope === "task" ? "任务" : "全局"}
              </Badge>
            </div>
            <p className="text-muted-foreground text-xs">{h.category || "—"}</p>
            <pre className="max-h-60 overflow-auto rounded bg-muted px-2 py-1 font-mono text-xs whitespace-pre-wrap">
              {h.content}
            </pre>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

// ---------------- 检索审计 ----------------

function LogsCard() {
  const [logs, setLogs] = React.useState<KnowledgeRetrievalLog[]>([]);
  React.useEffect(() => {
    void (async () => {
      try {
        setLogs(await api.knowledgeLogs(100));
      } catch (e) {
        toast.error(`读取审计失败：${(e as Error).message}`);
      }
    })();
  }, []);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">检索审计</CardTitle>
        <CardDescription>Agent 每次 search_knowledge 都记一行：查了什么、命中几篇、用的哪种模式。</CardDescription>
      </CardHeader>
      <CardContent>
        {logs.length === 0 ? (
          <p className="text-muted-foreground text-sm">还没有检索记录。</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>时间</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead>查询</TableHead>
                <TableHead>模式</TableHead>
                <TableHead className="text-right">命中</TableHead>
                <TableHead>任务</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.map((l) => (
                <TableRow key={l.id}>
                  <TableCell className="text-xs">{fmtTime(l.created_at)}</TableCell>
                  <TableCell className="text-xs">{l.agent_key || "—"}</TableCell>
                  <TableCell className="max-w-[320px] truncate text-xs" title={l.query}>
                    {l.query}
                  </TableCell>
                  <TableCell>
                    <Badge variant={l.mode === "semantic" ? "default" : "secondary"} className="text-xs">
                      {l.mode}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right text-xs">{l.hits}</TableCell>
                  <TableCell className="text-xs">{l.task_id ? `#${l.task_id}` : "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------- 新增 ----------------

function UploadDialog({ onDone }: { onDone: () => Promise<void> }) {
  const [open, setOpen] = React.useState(false);
  const [file, setFile] = React.useState<File | null>(null);
  const [scope, setScope] = React.useState<"global" | "task">("global");
  const [taskID, setTaskID] = React.useState("");
  const [category, setCategory] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function upload() {
    if (!file) {
      toast.error("先选一个文件");
      return;
    }
    if (scope === "task" && !taskID.trim()) {
      toast.error("任务知识必须指定任务");
      return;
    }
    setBusy(true);
    try {
      await api.uploadKnowledgeDoc(file, {
        scope,
        task_id: scope === "task" ? taskID.trim() : undefined,
        category: category.trim() || undefined,
      });
      toast.success("已上传，正在后台建索引");
      setOpen(false);
      setFile(null);
      await onDone();
    } catch (e) {
      toast.error(`上传失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          <UploadIcon className="size-4" /> 上传
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>上传知识文档</DialogTitle>
          <DialogDescription>
            文本类文件直接读；.docx 从 zip 里抽段落与表格（不依赖 python）。PDF 请先导出为文本。
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 py-2">
          <div className="grid gap-2">
            <Label className="text-sm">文件</Label>
            <input
              type="file"
              accept=".md,.markdown,.txt,.csv,.json,.log,.yaml,.yml,.html,.htm,.docx"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="text-sm"
            />
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label className="text-sm">范围</Label>
              <select
                className="h-9 rounded-md border bg-transparent px-2 text-sm"
                value={scope}
                onChange={(e) => setScope(e.target.value as "global" | "task")}
              >
                <option value="global">全局库</option>
                <option value="task">任务库</option>
              </select>
            </div>
            <div className="grid gap-2">
              <Label className="text-sm">任务 id（任务库必填）</Label>
              <Input
                value={taskID}
                disabled={scope !== "task"}
                placeholder="如 12"
                onChange={(e) => setTaskID(e.target.value)}
              />
            </div>
          </div>
          <div className="grid gap-2">
            <Label className="text-sm">分类（可选）</Label>
            <Input value={category} placeholder="如 越权 / 上传 / 业务逻辑" onChange={(e) => setCategory(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            取消
          </Button>
          <Button onClick={upload} disabled={busy}>
            {busy ? "上传中…" : "上传"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function NewDocDialog({ onDone }: { onDone: () => Promise<void> }) {
  const [open, setOpen] = React.useState(false);
  const [scope, setScope] = React.useState<"global" | "task">("global");
  const [taskID, setTaskID] = React.useState("");
  const [category, setCategory] = React.useState("");
  const [title, setTitle] = React.useState("");
  const [content, setContent] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function save() {
    if (!title.trim() || !content.trim()) {
      toast.error("标题与正文必填");
      return;
    }
    if (scope === "task" && !taskID.trim()) {
      toast.error("任务知识必须指定任务");
      return;
    }
    setBusy(true);
    try {
      await api.createKnowledgeDoc({
        scope,
        task_id: scope === "task" ? Number(taskID) : undefined,
        category: category.trim(),
        title: title.trim(),
        content,
      });
      toast.success("已保存，正在后台建索引");
      setOpen(false);
      setTitle("");
      setContent("");
      await onDone();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">手写一条</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>手写知识</DialogTitle>
          <DialogDescription>适合把一次复盘的方法论直接沉淀下来。</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 py-2">
          <div className="grid gap-2 sm:grid-cols-3">
            <div className="grid gap-2">
              <Label className="text-sm">范围</Label>
              <select
                className="h-9 rounded-md border bg-transparent px-2 text-sm"
                value={scope}
                onChange={(e) => setScope(e.target.value as "global" | "task")}
              >
                <option value="global">全局</option>
                <option value="task">任务</option>
              </select>
            </div>
            <div className="grid gap-2">
              <Label className="text-sm">任务 id</Label>
              <Input value={taskID} disabled={scope !== "task"} onChange={(e) => setTaskID(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label className="text-sm">分类</Label>
              <Input value={category} onChange={(e) => setCategory(e.target.value)} />
            </div>
          </div>
          <div className="grid gap-2">
            <Label className="text-sm">标题</Label>
            <Input value={title} onChange={(e) => setTitle(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label className="text-sm">正文</Label>
            <Textarea rows={10} className="font-mono text-xs" value={content} onChange={(e) => setContent(e.target.value)} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            取消
          </Button>
          <Button onClick={save} disabled={busy}>
            {busy ? "保存中…" : "保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}