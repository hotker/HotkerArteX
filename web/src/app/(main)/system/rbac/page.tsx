"use client";

import { KeyRoundIcon, PlusIcon, ShieldCheckIcon, Trash2Icon, UsersIcon } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
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
import type { AuditLog, RBACPermission, RBACRole, RBACUser } from "@/lib/types";

// 权限管理页：用户 / 角色与权限矩阵 / 审计日志。
//
// 后端是强制点（requireAuth 里统一拦截），这里只负责把"谁能做什么"讲清楚：
// 权限按模块分组勾选，系统角色只读展示（它们的授权由后端启动时确定性重建，
// 页面上改了也会被覆盖 —— 与其让人以为改了，不如直接标注"系统内置"）。

const ROLE_LABEL: Record<string, string> = {
  admin: "管理员",
  operator: "操作员",
  auditor: "审计员",
  viewer: "只读用户",
};

const SCOPE_LABEL: Record<string, string> = {
  all: "全部资源",
  assigned: "被授权的任务",
  own: "自己创建的",
};

function fmtTime(s: string): string {
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toLocaleString();
}

export default function RBACPage() {
  const [tab, setTab] = React.useState("users");
  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div>
        <h1 className="font-semibold text-xl">权限管理</h1>
        <p className="text-muted-foreground text-sm">
          用户、角色与权限矩阵。权限在服务端统一强制（未映射路由放行、管理员永不被拦）。
        </p>
      </div>
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="users">用户</TabsTrigger>
          <TabsTrigger value="roles">角色与权限</TabsTrigger>
          <TabsTrigger value="audit">审计日志</TabsTrigger>
        </TabsList>
        <TabsContent value="users" className="mt-4">
          <UsersCard />
        </TabsContent>
        <TabsContent value="roles" className="mt-4">
          <RolesCard />
        </TabsContent>
        <TabsContent value="audit" className="mt-4">
          <AuditCard />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ---------------- 用户 ----------------

function UsersCard() {
  const [users, setUsers] = React.useState<RBACUser[]>([]);
  const [roles, setRoles] = React.useState<RBACRole[]>([]);
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [u, r] = await Promise.all([api.rbacUsers(), api.rbacRoles()]);
      setUsers(u);
      setRoles(r);
    } catch (e) {
      toast.error(`加载失败：${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);
  React.useEffect(() => {
    void load();
  }, [load]);

  async function toggle(u: RBACUser, enabled: boolean) {
    try {
      await api.updateRBACUser(u.id, { display_name: u.display_name, enabled });
      toast.success(enabled ? `已启用 ${u.username}` : `已停用 ${u.username}（其会话立即失效）`);
      await load();
    } catch (e) {
      toast.error(`更新失败：${(e as Error).message}`);
    }
  }

  async function remove(u: RBACUser) {
    if (!window.confirm(`删除用户「${u.username}」？`)) return;
    try {
      await api.deleteRBACUser(u.id);
      toast.success("已删除");
      await load();
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    }
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <UsersIcon className="size-4" /> 用户
          </CardTitle>
          <CardDescription>停用或改密会立刻让该用户已签发的 token 失效（token_version 自增）。</CardDescription>
        </div>
        <UserDialog roles={roles} onDone={load} />
      </CardHeader>
      <CardContent>
        {loading ? (
          <p className="text-muted-foreground text-sm">加载中…</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>用户名</TableHead>
                <TableHead>昵称</TableHead>
                <TableHead>角色</TableHead>
                <TableHead>状态</TableHead>
                <TableHead className="text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((u) => (
                <TableRow key={u.id}>
                  <TableCell className="font-mono text-xs">
                    {u.username}
                    {u.is_builtin && (
                      <Badge variant="outline" className="ml-2 text-xs">
                        内置
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-xs">{u.display_name || "—"}</TableCell>
                  <TableCell className="text-xs">
                    {(u.roles || []).map((r) => ROLE_LABEL[r] ?? r).join("、") || "—"}
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={u.enabled}
                      disabled={u.is_builtin}
                      onCheckedChange={(v) => void toggle(u, v)}
                      aria-label="启用"
                    />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      <PasswordDialog user={u} onDone={load} />
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label="删除"
                        disabled={u.is_builtin}
                        onClick={() => void remove(u)}
                      >
                        <Trash2Icon className="size-4" />
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
  );
}

function UserDialog({ roles, onDone }: { roles: RBACRole[]; onDone: () => Promise<void> }) {
  const [open, setOpen] = React.useState(false);
  const [username, setUsername] = React.useState("");
  const [displayName, setDisplayName] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [picked, setPicked] = React.useState<string[]>(["operator"]);
  const [busy, setBusy] = React.useState(false);

  async function save() {
    if (!username.trim() || !password) {
      toast.error("用户名与密码必填");
      return;
    }
    setBusy(true);
    try {
      await api.createRBACUser({
        username: username.trim(),
        display_name: displayName.trim(),
        password,
        role_ids: picked,
      });
      toast.success("已创建");
      setOpen(false);
      setUsername("");
      setPassword("");
      await onDone();
    } catch (e) {
      toast.error(`创建失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <PlusIcon className="size-4" /> 新建用户
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>新建用户</DialogTitle>
          <DialogDescription>密码走 bcrypt 存储；至少 8 位。</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 py-2">
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label className="text-sm">用户名</Label>
              <Input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="alice" />
            </div>
            <div className="grid gap-2">
              <Label className="text-sm">昵称（可选）</Label>
              <Input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
            </div>
          </div>
          <div className="grid gap-2">
            <Label className="text-sm">初始密码</Label>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label className="text-sm">角色</Label>
            <div className="flex flex-wrap gap-3">
              {roles.map((r) => (
                <label key={r.id} className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={picked.includes(r.id)}
                    onCheckedChange={(v) =>
                      setPicked((cur) => (v === true ? [...cur, r.id] : cur.filter((x) => x !== r.id)))
                    }
                  />
                  {r.name}
                </label>
              ))}
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            取消
          </Button>
          <Button onClick={save} disabled={busy}>
            {busy ? "创建中…" : "创建"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PasswordDialog({ user, onDone }: { user: RBACUser; onDone: () => Promise<void> }) {
  const [open, setOpen] = React.useState(false);
  const [password, setPassword] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function save() {
    setBusy(true);
    try {
      await api.updateRBACUser(user.id, { display_name: user.display_name, password });
      toast.success("密码已重置，该用户需重新登录");
      setOpen(false);
      setPassword("");
      await onDone();
    } catch (e) {
      toast.error(`重置失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="重置密码">
          <KeyRoundIcon className="size-4" />
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>重置「{user.username}」的密码</DialogTitle>
          <DialogDescription>重置后该用户所有已签发的 token 立即失效。</DialogDescription>
        </DialogHeader>
        <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="新密码（≥8 位）" />
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            取消
          </Button>
          <Button onClick={save} disabled={busy || password.length < 8}>
            {busy ? "保存中…" : "重置"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------- 角色与权限矩阵 ----------------

function RolesCard() {
  const [roles, setRoles] = React.useState<RBACRole[]>([]);
  const [perms, setPerms] = React.useState<RBACPermission[]>([]);
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [r, meta] = await Promise.all([api.rbacRoles(), api.rbacMetadata()]);
      setRoles(r);
      setPerms(meta.permissions);
    } catch (e) {
      toast.error(`加载失败：${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);
  React.useEffect(() => {
    void load();
  }, [load]);

  const groups = React.useMemo(() => {
    const m = new Map<string, RBACPermission[]>();
    for (const p of perms) {
      const list = m.get(p.group) ?? [];
      list.push(p);
      m.set(p.group, list);
    }
    return [...m.entries()];
  }, [perms]);

  async function remove(r: RBACRole) {
    if (!window.confirm(`删除角色「${r.name}」？绑定它的用户会失去该角色。`)) return;
    try {
      await api.deleteRBACRole(r.id);
      toast.success("已删除");
      await load();
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    }
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheckIcon className="size-4" /> 角色与权限矩阵
          </CardTitle>
          <CardDescription>
            系统角色的授权由服务端启动时确定性重建（新增权限会自动下发），因此只读；自定义角色可自由勾选。
          </CardDescription>
        </div>
        <RoleDialog perms={perms} onDone={load} />
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {loading ? (
          <p className="text-muted-foreground text-sm">加载中…</p>
        ) : (
          roles.map((r) => (
            <div key={r.id} className="flex flex-col gap-2 rounded-md border p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-sm">{r.name}</span>
                <Badge variant="outline" className="text-xs">
                  {SCOPE_LABEL[r.scope] ?? r.scope}
                </Badge>
                {r.is_system ? (
                  <Badge variant="secondary" className="text-xs">
                    系统内置
                  </Badge>
                ) : (
                  <Button variant="ghost" size="icon" aria-label="删除角色" onClick={() => void remove(r)}>
                    <Trash2Icon className="size-4" />
                  </Button>
                )}
                <span className="text-muted-foreground ml-auto text-xs">{r.permissions.length} 项权限</span>
              </div>
              {r.description && <p className="text-muted-foreground text-xs">{r.description}</p>}
              <div className="flex flex-wrap gap-1">
                {r.permissions.map((k) => (
                  <span key={k} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">
                    {k}
                  </span>
                ))}
              </div>
            </div>
          ))
        )}
        <p className="text-muted-foreground text-xs">
          共 {perms.length} 项权限、{groups.length} 个模块。系统的强制口径：所有 <code>:read</code>
          给全部角色；功能类写权限给操作员；账号/核心配置/LLM 的写权限只给管理员。
        </p>
      </CardContent>
    </Card>
  );
}

function RoleDialog({ perms, onDone }: { perms: RBACPermission[]; onDone: () => Promise<void> }) {
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [scope, setScope] = React.useState("assigned");
  const [picked, setPicked] = React.useState<string[]>([]);
  const [busy, setBusy] = React.useState(false);

  const groups = React.useMemo(() => {
    const m = new Map<string, RBACPermission[]>();
    for (const p of perms) {
      const list = m.get(p.group) ?? [];
      list.push(p);
      m.set(p.group, list);
    }
    return [...m.entries()];
  }, [perms]);

  async function save() {
    if (!name.trim()) {
      toast.error("角色名必填");
      return;
    }
    setBusy(true);
    try {
      await api.createRBACRole({ name: name.trim(), description: description.trim(), scope, permissions: picked });
      toast.success("已创建");
      setOpen(false);
      setName("");
      setPicked([]);
      await onDone();
    } catch (e) {
      toast.error(`创建失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <PlusIcon className="size-4" /> 新建角色
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>新建角色</DialogTitle>
          <DialogDescription>按模块勾选权限；scope 决定该角色能触达哪些资源。</DialogDescription>
        </DialogHeader>
        <div className="flex max-h-[60vh] flex-col gap-3 overflow-auto py-2">
          <div className="grid gap-2 sm:grid-cols-3">
            <div className="grid gap-2">
              <Label className="text-sm">角色名</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="如 渗透工程师" />
            </div>
            <div className="grid gap-2">
              <Label className="text-sm">资源范围</Label>
              <select
                className="h-9 rounded-md border bg-transparent px-2 text-sm"
                value={scope}
                onChange={(e) => setScope(e.target.value)}
              >
                <option value="all">全部资源</option>
                <option value="assigned">被授权的任务</option>
                <option value="own">自己创建的</option>
              </select>
            </div>
            <div className="grid gap-2">
              <Label className="text-sm">说明</Label>
              <Input value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
          </div>
          {groups.map(([group, list]) => (
            <div key={group} className="flex flex-col gap-1 rounded-md border p-2">
              <div className="flex items-center justify-between">
                <span className="font-medium text-xs">{group}</span>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() =>
                    setPicked((cur) => {
                      const all = list.every((p) => cur.includes(p.key));
                      return all ? cur.filter((k) => !list.some((p) => p.key === k)) : [...new Set([...cur, ...list.map((p) => p.key)])];
                    })
                  }
                >
                  全选/清空
                </Button>
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1">
                {list.map((p) => (
                  <label key={p.key} className="flex items-center gap-1.5 text-xs" title={p.description}>
                    <Checkbox
                      checked={picked.includes(p.key)}
                      onCheckedChange={(v) =>
                        setPicked((cur) => (v === true ? [...cur, p.key] : cur.filter((k) => k !== p.key)))
                      }
                    />
                    <span className="font-mono">{p.key}</span>
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            取消
          </Button>
          <Button onClick={save} disabled={busy}>
            {busy ? "创建中…" : "创建"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------- 审计 ----------------

function AuditCard() {
  const [logs, setLogs] = React.useState<AuditLog[]>([]);
  const [total, setTotal] = React.useState(0);
  const [cats, setCats] = React.useState<string[]>([]);
  const [actor, setActor] = React.useState("");
  const [category, setCategory] = React.useState("");
  const [q, setQ] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.auditLogs({ actor, category, q, limit: 200 });
      setLogs(r.logs);
      setTotal(r.total);
      setCats(r.categories);
    } catch (e) {
      toast.error(`加载失败：${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, [actor, category, q]);
  React.useEffect(() => {
    void load();
  }, [load]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">审计日志</CardTitle>
        <CardDescription>
          谁、什么时候、对什么做了什么。业务日志（server_logs）用于排障，这张表用于合规。
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap gap-2">
          <Input
            className="w-40"
            placeholder="按用户筛选"
            value={actor}
            onChange={(e) => setActor(e.target.value)}
          />
          <select
            className="h-9 rounded-md border bg-transparent px-2 text-sm"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
          >
            <option value="">全部类别</option>
            {cats.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <Input
            className="w-64"
            placeholder="搜索动作（如 DELETE /api/tasks）"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <span className="text-muted-foreground self-center text-xs">共 {total} 条</span>
        </div>
        {loading ? (
          <p className="text-muted-foreground text-sm">加载中…</p>
        ) : logs.length === 0 ? (
          <p className="text-muted-foreground text-sm">没有匹配的记录。</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>时间</TableHead>
                <TableHead>用户</TableHead>
                <TableHead>类别</TableHead>
                <TableHead>动作</TableHead>
                <TableHead>结果</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>说明</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.map((l) => (
                <TableRow key={l.id}>
                  <TableCell className="whitespace-nowrap text-xs">{fmtTime(l.created_at)}</TableCell>
                  <TableCell className="text-xs">{l.actor || "—"}</TableCell>
                  <TableCell className="text-xs">{l.category}</TableCell>
                  <TableCell className="max-w-[260px] truncate font-mono text-xs" title={l.action}>
                    {l.action}
                  </TableCell>
                  <TableCell>
                    <Badge variant={l.result === "success" ? "secondary" : "outline"} className="text-xs">
                      {l.result}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs">{l.ip}</TableCell>
                  <TableCell className="max-w-[220px] truncate text-xs" title={l.message}>
                    {l.message}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}