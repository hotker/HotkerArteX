"use client";

import * as React from "react";

import {
  CheckCircle2Icon,
  DownloadIcon,
  ExternalLinkIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  TriangleAlertIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { api, handleUnauthorized, probeSession, sseUrl } from "@/lib/api";
import type { UpdateCheck, UpdateProgress } from "@/lib/types";

/** 等待新版本上线的最长时间。一次升级要经过三次进程启动（暂存 → 换装 → 新版），
 *  每次都是秒级，三分钟足够覆盖慢磁盘和 Docker 容器重建。 */
const RESTART_TIMEOUT_MS = 180_000;

function humanSize(n?: number): string {
  if (!n || n <= 0) return "";
  const units = ["B", "KB", "MB", "GB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function UpdateCard() {
  const [info, setInfo] = React.useState<UpdateCheck | null>(null);
  const [checking, setChecking] = React.useState(true);
  const [progress, setProgress] = React.useState<UpdateProgress | null>(null);
  // 与 progress 分开：暂存完成后进程就没了，SSE 会断，此时要切到轮询 /api/health。
  const [restarting, setRestarting] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  // 进度流的句柄与「已暂存」标记：onerror 要靠后者区分"正常重启断线"和"失败"。
  const esRef = React.useRef<EventSource | null>(null);
  const stagedRef = React.useRef(false);

  // quiet 同时决定要不要绕过后端缓存：进页面时的自动检查用缓存（顶栏刚查过），
  // 用户手动点「检查更新」则强制回源，否则刚发布的版本要等缓存过期才看得到。
  const check = React.useCallback((quiet = false) => {
    setChecking(true);
    api
      .checkUpdate(!quiet)
      .then((r) => {
        setInfo(r);
        if (!quiet) {
          if (r.error) toast.error("检查更新失败：" + r.error);
          else if (r.has_update) toast.success(`发现新版本 ${r.latest}`);
          else if (r.comparable) toast.success("当前已是最新版本");
        }
      })
      .catch((e) => {
        if (!quiet) toast.error("检查更新失败：" + (e as Error).message);
      })
      .finally(() => setChecking(false));
  }, []);

  React.useEffect(() => {
    check(true);
  }, [check]);

  // 轮询 /api/health 直到版本号变化。
  //
  // 判据必须是"版本变了"而不是"能连上了"：换装过程中旧版本会短暂地重新起来一次
  // （那一次只负责把 foxker.new 换上去然后立刻退出），只看连通性会误判成功。
  const waitForNewVersion = React.useCallback(async (fromVersion: string) => {
    stagedRef.current = true;
    setRestarting(true);
    const deadline = Date.now() + RESTART_TIMEOUT_MS;
    while (Date.now() < deadline) {
      await sleep(2000);
      try {
        const r = await fetch("/api/health", { cache: "no-store" });
        if (r.ok) {
          const j = (await r.json()) as { version?: string };
          if (j.version && j.version !== fromVersion) {
            toast.success(`已更新到 ${j.version}，正在重新加载页面`);
            await sleep(800);
            window.location.reload();
            return;
          }
        }
      } catch {
        // 重启窗口内连不上是预期的，继续轮询。
      }
    }
    setRestarting(false);
    toast.error("等待服务重启超时。请检查后端日志，或确认 Foxker 是通过 start.sh / start.bat 启动的。");
  }, []);

  // 订阅更新进度。SSE 不走 Next 的 /api 重写（那层会缓冲，事件推不出来）。
  //
  // 流句柄放在 ref 里：原来是局部 const，组件卸载（切页/关设置页）时没人关闭它，
  // 连接和监听会一直活到标签页关闭；而 onerror 又无条件关闭，导致暂存前断线时
  // busy 永远为 true、所有按钮禁用、界面停在「准备中…」。
  const openStream = React.useCallback(
    (fromVersion: string) => {
      esRef.current?.close();
      const es = new EventSource(sseUrl("/api/update/stream"));
      esRef.current = es;
      es.onmessage = (ev) => {
        let p: UpdateProgress;
        try {
          p = JSON.parse(ev.data) as UpdateProgress;
        } catch {
          return;
        }
        setProgress(p);
        if (p.phase === "failed") {
          es.close();
          esRef.current = null;
          setBusy(false);
          toast.error("更新失败：" + (p.error || p.message));
          return;
        }
        if (p.phase === "staged") {
          es.close();
          esRef.current = null;
          void waitForNewVersion(fromVersion);
        }
      };
      es.onerror = () => {
        // 进程退出时 SSE 必然断开。已经进入「等待重启」时这属于正常现象，交给
        // /api/health 轮询继续判定；否则（401、代理中断、后端重启）流不会自动
        // 恢复，必须结束 busy 并告诉用户，否则界面永远卡在「准备中…」。
        es.close();
        if (esRef.current === es) esRef.current = null;
        if (stagedRef.current) return;
        // 区分「令牌失效」和「传输中断」：前者重试多少次都不会成功，直接清凭证
        // 回登录页；后者保留原来的「请重试」提示。
        void probeSession().then((state) => {
          if (state === "unauthorized") {
            handleUnauthorized();
            return;
          }
          setBusy(false);
          setProgress(null);
          toast.error("更新进度连接中断，请重试");
        });
      };
      return es;
    },
    [waitForNewVersion],
  );

  // 卸载时关闭流，避免离开设置页后仍挂着订阅。
  React.useEffect(() => () => esRef.current?.close(), []);

  const doUpdate = () => {
    if (!info) return;
    const from = info.current;
    const ok = window.confirm(
      `确定更新到 ${info.latest}？\n\n` +
        "更新会重启程序，正在运行的任务会被中断。\n" +
        (info.mode === "docker"
          ? "\n注意：容器内更新只替换程序本身，不会更新镜像里的 playwright / nmap 等工具链；" +
            "若新版本依赖新工具，请改用 docker compose pull。"
          : ""),
    );
    if (!ok) return;

    setBusy(true);
    stagedRef.current = false;
    setProgress({ phase: "downloading", percent: 0, message: "准备中…" });
    const es = openStream(from);
    api.applyUpdate().catch((e) => {
      es.close();
      if (esRef.current === es) esRef.current = null;
      setBusy(false);
      setProgress(null);
      toast.error("启动更新失败：" + (e as Error).message);
    });
  };

  const doRollback = () => {
    if (!info) return;
    if (
      !window.confirm(
        "回滚到上一版本？\n\n程序会重启，正在运行的任务会被中断。\n注意：数据库结构不会回退，旧版本可能无法识别新版写入的数据。",
      )
    )
      return;
    const from = info.current;
    setBusy(true);
    api
      .rollbackUpdate()
      .then(() => {
        toast.success("已切换到上一版本，正在重启…");
        void waitForNewVersion(from);
      })
      .catch((e) => {
        setBusy(false);
        toast.error("回滚失败：" + (e as Error).message);
      });
  };

  const phase = progress?.phase;
  const showProgress = busy || restarting;
  // 只有下载阶段拿得到真实百分比（按 Content-Length 算）。校验/解压/等待重启都是
  // 时长不可知的阶段，进度条填满并加个脉冲动画表示"在忙但说不准还要多久"。
  const downloading = !restarting && phase === "downloading";
  const pct = downloading ? Math.max(progress?.percent ?? 0, 0) : 100;

  return (
    // 设置页是多列瀑布流布局，卡片自己负责行间距并禁止跨列断开（见 page.tsx 的注释）。
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <DownloadIcon className="size-4" />
          版本与更新
        </CardTitle>
        <CardDescription>从 GitHub 检查并安装新版本。更新会重启程序，正在运行的任务会被中断。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-muted-foreground">当前版本</span>
          <Badge variant="secondary" className="font-mono">
            {info?.current ?? "…"}
          </Badge>
          {info && (
            <>
              <Badge variant="outline" className="font-mono">
                {info.os}/{info.arch}
              </Badge>
              <Badge variant="outline">{info.mode === "docker" ? "Docker" : "独立程序"}</Badge>
            </>
          )}
          {info?.latest && (
            <>
              <span className="text-muted-foreground">最新版本</span>
              <Badge variant={info.has_update ? "default" : "secondary"} className="font-mono">
                {info.latest}
              </Badge>
            </>
          )}
          {info?.html_url && (
            <a
              href={info.html_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-muted-foreground underline-offset-4 hover:underline"
            >
              更新日志 <ExternalLinkIcon className="size-3" />
            </a>
          )}
        </div>

        {info?.boot_notice && (
          <p className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-400">
            <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
            {info.boot_notice}
          </p>
        )}

        {info?.error && (
          <p className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">
            <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
            无法连接 GitHub：{info.error}
            {"　"}可在上方配置全局代理后重试。
          </p>
        )}

        {info && !info.comparable && info.reason && <p className="text-xs text-muted-foreground">{info.reason}</p>}

        {info?.has_update && info.asset_available === false && (
          <p className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">
            <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
            {info.latest} 没有提供 {info.os}/{info.arch} 的发布包（缺少 {info.asset}），无法自动更新。
          </p>
        )}

        {info?.has_update && info.asset_available !== false && (
          <p className="text-xs text-muted-foreground">
            将下载 <span className="font-mono">{info.asset}</span>
            {info.size ? `（${humanSize(info.size)}）` : ""}，校验 SHA256 并冒烟测试后才会替换，失败自动保留当前版本。
          </p>
        )}

        {info && !info.has_update && info.comparable && !info.error && (
          <p className="flex items-center gap-2 text-xs text-muted-foreground">
            <CheckCircle2Icon className="size-3.5 text-emerald-600" />
            当前已是最新版本。
          </p>
        )}

        {info?.mode === "docker" && info.has_update && (
          <p className="text-xs text-muted-foreground">
            Docker 下的更新只替换程序本身，不更新镜像里的 playwright / nmap 等工具链，且
            <span className="font-mono"> docker compose up -d </span>
            重建容器后会退回镜像自带的版本。需要连镜像一起升级请执行
            <span className="font-mono"> docker compose pull foxker &amp;&amp; docker compose up -d foxker</span>。
          </p>
        )}

        {showProgress && (
          <div className="space-y-1.5">
            <Progress value={pct} className={downloading ? undefined : "animate-pulse"} />
            <p className="text-xs text-muted-foreground">
              {restarting ? "正在重启并应用新版本，请稍候（页面会自动刷新）…" : progress?.message}
            </p>
          </div>
        )}

        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={() => check(false)} disabled={checking || busy || restarting}>
            <RefreshCwIcon className={checking ? "size-4 animate-spin" : "size-4"} />
            检查更新
          </Button>
          <Button
            size="sm"
            onClick={doUpdate}
            disabled={busy || restarting || !info?.has_update || info?.asset_available === false}
          >
            <DownloadIcon className="size-4" />
            {info?.has_update ? `更新到 ${info.latest}` : "立即更新"}
          </Button>
          {info?.has_backup && (
            <Button variant="ghost" size="sm" onClick={doRollback} disabled={busy || restarting}>
              <RotateCcwIcon className="size-4" />
              回滚到上一版本
            </Button>
          )}
        </div>

        <p className="text-xs text-muted-foreground">
          一键更新依赖守护脚本重启程序。请通过 <span className="font-mono">start.sh</span>（Windows 为
          <span className="font-mono"> start.bat</span>）启动 Foxker；直接运行 Foxker 本体时，程序退出后不会被自动拉起。
        </p>
      </CardContent>
    </Card>
  );
}
