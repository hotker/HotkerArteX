// Package version 是程序版本的唯一来源。
//
// 之前版本号散在三处且各自漂移：
//   - cmd/artex/main.go 的 `var version = "dev"`（源码构建永远显示 dev）
//   - web/package.json（前端版本）
//   - web/package-lock.json（npm ci 不会回写，于是长期停在旧版本）
//
// 后果就是"后台显示的版本号还是旧的"：二进制说 dev、锁文件说 2.3.1、package.json
// 说 2.5.3，谁也说不准当前是哪个版本，一键更新的"是否最新"判断也就没了基准。
//
// 现在以本文件为唯一真值：main 的默认版本取自它，release 构建仍可用
// `-ldflags "-X main.version=<tag>"` 覆盖；version_test.go 会校验它与
// web/package.json、web/package-lock.json、CHANGELOG 最新条目一致 —— 任何一处
// 忘改都会在 `go test ./version` 里失败，而不是等到发布后才发现。
package version

// Version 是当前程序版本，形如 "2.5.4"（不带 v 前缀，release tag 才有 v）。
// 必须是纯净三段式：selfupdate.parseVersion 只接受可比较的版本号，
// 带后缀（如 2.5.4-rc1）会让"一键更新"整体禁用。
const Version = "3.5.1"

// DisplaySuffix 用于开发构建的额外标记（正式 release 不设）。
// 例：go build -ldflags "-X main.version=$(...)" 时不需要它。
const DisplaySuffix = ""
