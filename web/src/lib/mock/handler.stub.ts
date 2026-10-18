// 生产构建（MOCK=false）下，next.config.mjs 的 turbopack.resolveAlias 会把
// "@/lib/mock/handler" 指向本文件，从而把真正的 6.7k 行 mock/handler.ts +
// mock/data.ts 排除出模块图，不再打进 web/out（演示数据含假漏洞利用命令，
// 不应随生产二进制分发）。
//
// 正常情况下本文件永远不会被调用：所有 mockHandle 调用点都在 `if (MOCK)` 分支里，
// 而 MOCK 在生产构建里被内联为 false。这里抛错只是纵深防御——若某条路径真的走到
// 这里，宁可 loud-fail，也不要静默返回演示数据。
export async function mockHandle<T>(): Promise<T> {
  throw new Error(
    "[artex] mock handler 不应在生产构建中被调用（MOCK 未启用却触发了 mock 分支）",
  );
}

export function mockReport(_task?: string): string {
  throw new Error(
    "[artex] mock 报告不应在生产构建中被返回（MOCK 未启用却触发了 mock 分支）",
  );
}
