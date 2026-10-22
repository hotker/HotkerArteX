package server

import (
	"bytes"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Workspace file manager — browse / view / edit / download / upload / delete the
// shared work dir (s.m.dir), where all agents write their artifacts. Every path is
// confined to the work dir root (traversal via ".." is neutralised). All routes sit
// behind requireAuth (see Handler()).

const (
	maxWorkspaceRead   = 2 << 20   // 2 MiB: files bigger than this aren't inlined for view/edit (download instead)
	maxWorkspaceUpload = 512 << 20 // 512 MiB per upload request
)

// sensitiveWorkspaceTrees are system files that live under the shared work dir
// but must never be exposed through the workspace manager, because they are
// not agent artifacts: the traffic tree holds the MITM CA *private key*
// (mitmproxy-ca.pem — holding it forges TLS for any domain) plus a plaintext
// capture index, the evidence tree holds raw target data, and jwt.key is the
// session signing key. They get dedicated APIs instead (e.g. /api/traffic/ca-cert).
var sensitiveWorkspaceTrees = []string{"traffic", "evidence", "jwt.key", "jwt.key.migrated"}

// isSensitiveWorkspacePath reports whether a workspace-relative path (or the
// top-level entry under a requested directory) falls inside a protected tree.
//
// The comparison is case-insensitive: on APFS (macOS default) and NTFS the
// filesystem resolves "Traffic/_ca/mitmproxy-ca.pem" to the real traffic tree,
// so an exact-match check would hand out the MITM CA private key to anyone able
// to spell the path differently. EvalSymlinks does not canonicalise case, so the
// resolved-path guard has the same hole and this check is the last line.
func isSensitiveWorkspacePath(rel string) bool {
	top := strings.TrimPrefix(strings.TrimSpace(rel), "/")
	if i := strings.IndexByte(top, '/'); i >= 0 {
		top = top[:i]
	}
	for _, s := range sensitiveWorkspaceTrees {
		if strings.EqualFold(top, s) {
			return true
		}
	}
	return false
}

// wsSensitiveReal reports whether abs, with symlinks resolved, points at one of
// the protected entries in dir. Unlike the string comparison above it reads the
// directory, so it matches whatever spelling the filesystem actually stored and
// catches a differently-cased path reaching the same inode.
func wsSensitiveReal(dir, abs string) bool {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		root = dir
	}
	realAbs, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return false // does not exist yet; nothing to serve
	}
	rel, err := filepath.Rel(root, realAbs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	top := strings.TrimPrefix(filepath.ToSlash(rel), "/")
	if i := strings.IndexByte(top, '/'); i >= 0 {
		top = top[:i]
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() != top {
			continue
		}
		for _, s := range sensitiveWorkspaceTrees {
			if strings.EqualFold(e.Name(), s) {
				return true
			}
		}
	}
	return false
}

// wsResolve maps a user-supplied relative path to an absolute path INSIDE the work
// dir. It returns ok=false if the path would escape the root. filepath.Clean on a
// rooted copy collapses any ".." so nothing can climb above the root.
func (s *Server) wsResolve(rel string) (string, bool) {
	base := filepath.Clean(s.m.dir)
	rel = strings.TrimPrefix(strings.TrimSpace(rel), "/")
	clean := filepath.Clean("/" + rel) // e.g. "/a/../../etc" → "/etc" (still rooted at "/")
	abs := filepath.Clean(filepath.Join(base, clean))
	if abs != base && !strings.HasPrefix(abs, base+string(os.PathSeparator)) {
		return "", false
	}
	return abs, true
}

// wsGuard refuses operations on protected system paths (see
// sensitiveWorkspaceTrees): the MITM CA private key, the traffic index, raw
// evidence and jwt.key must not be reachable from the workspace manager.
func (s *Server) wsGuard(w http.ResponseWriter, abs string) bool {
	if isSensitiveWorkspacePath(s.wsRel(abs)) {
		writeErr(w, 403, "该路径为系统保留文件，无法通过工作区访问")
		return false
	}
	return true
}

// wsRealEscape reports whether abs escapes the work dir *after* resolving
// symbolic links, and returns the real path (or "" on a stat error). The lexical
// checks in wsResolve only look at the requested string; a symlink an agent (or
// anyone with write access to the work dir) drops into it — e.g.
// `ln -s traffic/_ca/mitmproxy-ca.pem notes.txt` — resolves to a protected file
// while the requested path itself looks perfectly ordinary. Guarding on the
// lexical path alone would therefore hand out the MITM CA private key.
//
// A target that does not exist yet (write/mkdir/upload destinations) is checked
// through its deepest existing ancestor, so creating files under a symlinked
// directory is caught as well.
func (s *Server) wsReal(abs string) (string, error) {
	real, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return real, nil
	}
	// Missing tail (the common case for create): resolve the parent that does
	// exist and append the rest lexically.
	parent := filepath.Dir(abs)
	rest := []string{filepath.Base(abs)}
	for {
		realParent, perr := filepath.EvalSymlinks(parent)
		if perr == nil {
			parts := append([]string{realParent}, rest...)
			return filepath.Join(parts...), nil
		}
		if parent == filepath.Dir(parent) {
			return "", err // nothing along the path exists
		}
		rest = append([]string{filepath.Base(parent)}, rest...)
		parent = filepath.Dir(parent)
	}
}

// wsRealRel renders the symlink-resolved path as a path relative to the
// symlink-resolved work dir root. ok=false means abs resolves to somewhere
// outside the work dir (or along a path that does not exist).
//
// Both sides are resolved: m.dir itself may sit under a symlink (macOS
// /var → /private/var, a bind-mounted Docker volume, ...), so mixing a
// resolved target with an unresolved base yields "../.." and makes every
// containment check vacuous.
func (s *Server) wsRealRel(abs string) (string, bool) {
	base := filepath.Clean(s.m.dir)
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		realBase = base
	}
	real, err := s.wsReal(abs)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(realBase, real)
	if err != nil {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", false
	}
	if rel == "." {
		return "", true
	}
	return filepath.ToSlash(rel), true
}

// wsGuardReal is wsGuard over the symlink-resolved path: it refuses any target
// that really lives inside a protected tree or outside the work dir, no matter
// how it was reached. Guarding only the requested string is not enough — a
// symlink dropped into the work dir (by an agent, or by anyone the agent runs
// code as) turns `notes.txt` into the MITM CA private key.
func (s *Server) wsGuardReal(w http.ResponseWriter, abs string) bool {
	rel, ok := s.wsRealRel(abs)
	if !ok {
		writeErr(w, 403, "路径解析后超出工作区")
		return false
	}
	if isSensitiveWorkspacePath(rel) || wsSensitiveReal(s.m.dir, abs) {
		writeErr(w, 403, "该路径为系统保留文件，无法通过工作区访问")
		return false
	}
	return true
}

// wsRel renders an absolute path back as a workspace-relative path (forward slashes).
func (s *Server) wsRel(abs string) string {
	base := filepath.Clean(s.m.dir)
	rel, err := filepath.Rel(base, abs)
	if err != nil || rel == "." {
		return ""
	}
	return filepath.ToSlash(rel)
}

type wsEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"` // unix millis
}

// GET /api/workspace/list?path=<rel>
func (s *Server) wsList(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	if !s.wsGuard(w, abs) || !s.wsGuardReal(w, abs) {
		return
	}
	fi, err := os.Stat(abs)
	if err != nil {
		writeErr(w, 404, "路径不存在")
		return
	}
	if !fi.IsDir() {
		writeErr(w, 400, "不是目录")
		return
	}
	ents, err := os.ReadDir(abs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]wsEntry, 0, len(ents))
	for _, e := range ents {
		entryAbs := filepath.Join(abs, e.Name())
		// Hide protected system trees (traffic/ CA key, evidence/, jwt.key) from
		// the browser; per-handler gates refuse anything deeper inside them. A
		// symlink pointing into one is hidden too, so the listing never advertises
		// a path the guards below would refuse anyway.
		realRel, realOK := s.wsRealRel(entryAbs)
		if isSensitiveWorkspacePath(s.wsRel(entryAbs)) || (realOK && isSensitiveWorkspacePath(realRel)) || !realOK {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, wsEntry{
			Name:  e.Name(),
			Path:  s.wsRel(entryAbs),
			Dir:   e.IsDir(),
			Size:  info.Size(),
			MTime: info.ModTime().UnixMilli(),
		})
	}
	// 目录在前，各自按名称排序。
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "entries": out})
}

// wsAudit records a mutating workspace operation to the backend log (which is
// persisted to server_logs and viewable on the 日志 page), so write/delete/
// upload actions have an auditable trail beyond the JWT gate. Read/download are
// intentionally not logged to keep the log signal-to-noise usable.
func wsAudit(r *http.Request, action, detail string) {
	log.Printf("[ws] %s ip=%s %s", action, clientIP(r), detail)
}

// GET /api/workspace/read?path=<rel> — inline text for view/edit. Binary or oversize
// files return {binary:true}/{too_large:true} with no content (use download instead).
func (s *Server) wsRead(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	if !s.wsGuard(w, abs) || !s.wsGuardReal(w, abs) {
		return
	}
	fi, err := os.Stat(abs)
	if err != nil {
		writeErr(w, 404, "文件不存在")
		return
	}
	if fi.IsDir() {
		writeErr(w, 400, "是目录，不能作为文件读取")
		return
	}
	if fi.Size() > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "too_large": true, "binary": true})
		return
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "binary": true})
		return
	}
	writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "binary": false, "content": string(data)})
}

// POST /api/workspace/write  {path, content} — create/overwrite a text file.
func (s *Server) wsWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	abs, ok := s.wsResolve(req.Path)
	if !ok || abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "非法路径")
		return
	}
	if !s.wsGuard(w, abs) || !s.wsGuardReal(w, abs) {
		return
	}
	if fi, err := os.Stat(abs); err == nil && fi.IsDir() {
		writeErr(w, 400, "目标是目录")
		return
	}
	// Writing through a symlink would land on its target (e.g. the CA key);
	// os.WriteFile follows links, so refuse the link itself as well.
	if fi, err := os.Lstat(abs); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		writeErr(w, 400, "目标是符号链接，拒绝写入")
		return
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := os.WriteFile(abs, []byte(req.Content), 0o644); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	wsAudit(r, "write", "path="+s.wsRel(abs)+" bytes="+strconv.Itoa(len(req.Content)))
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

// POST /api/workspace/mkdir  {path}
func (s *Server) wsMkdir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	abs, ok := s.wsResolve(req.Path)
	if !ok || abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "非法路径")
		return
	}
	if !s.wsGuard(w, abs) || !s.wsGuardReal(w, abs) {
		return
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	wsAudit(r, "mkdir", "path="+s.wsRel(abs))
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

// DELETE /api/workspace/delete?path=<rel> — removes a file or a directory tree
// (confined to the work dir; the root itself can't be deleted).
func (s *Server) wsDelete(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	if abs == filepath.Clean(s.m.dir) {
		writeErr(w, 400, "不能删除工作区根目录")
		return
	}
	if !s.wsGuard(w, abs) || !s.wsGuardReal(w, abs) {
		return
	}
	if _, err := os.Stat(abs); err != nil {
		writeErr(w, 404, "路径不存在")
		return
	}
	// os.RemoveAll removes a symlink itself, not its target, so a link pointing
	// into a protected tree would be a way to *delete* that tree's entry point —
	// refuse it for the same reason the read paths refuse to follow it.
	if fi, err := os.Lstat(abs); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		writeErr(w, 400, "目标是符号链接，拒绝删除")
		return
	}
	if err := os.RemoveAll(abs); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	wsAudit(r, "delete", "path="+s.wsRel(abs))
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/workspace/download?path=<rel> — stream a file as an attachment.
func (s *Server) wsDownload(w http.ResponseWriter, r *http.Request) {
	abs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	if !s.wsGuard(w, abs) || !s.wsGuardReal(w, abs) {
		return
	}
	fi, err := os.Stat(abs)
	if err != nil || fi.IsDir() {
		writeErr(w, 404, "文件不存在")
		return
	}
	// Only regular files. An agent has shell access to its work dir and can drop a
	// FIFO or device node there; http.ServeFile opens the target, so a FIFO with no
	// writer blocks the handler goroutine (and its connection) forever.
	if !fi.Mode().IsRegular() {
		writeErr(w, 400, "只能下载普通文件")
		return
	}
	name := filepath.Base(abs)
	// RFC 5987 filename* keeps non-ASCII names intact; plain filename is the fallback.
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(name)+"\"; filename*=UTF-8''"+url.PathEscape(name))
	http.ServeFile(w, r, abs)
}

// POST /api/workspace/upload?path=<dir> — multipart form field "file" (one or more).
func (s *Server) wsUpload(w http.ResponseWriter, r *http.Request) {
	dirAbs, ok := s.wsResolve(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "非法路径")
		return
	}
	if !s.wsGuard(w, dirAbs) || !s.wsGuardReal(w, dirAbs) {
		return
	}
	if fi, err := os.Stat(dirAbs); err != nil || !fi.IsDir() {
		writeErr(w, 400, "目标目录不存在")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWorkspaceUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "解析上传失败或超出大小限制："+err.Error())
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "缺少上传文件(表单字段 file)")
		return
	}
	saved := 0
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." {
			continue
		}
		destAbs, okd := s.wsResolve(filepath.Join(s.wsRel(dirAbs), name))
		if !okd {
			continue
		}
		// The directory itself was checked above, but the destination may be an
		// existing symlink placed inside it — os.Create would then overwrite the
		// link target.
		if !s.wsGuardReal(w, destAbs) {
			return
		}
		if fi, err := os.Lstat(destAbs); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			writeErr(w, 400, "目标文件是符号链接，拒绝覆盖")
			return
		}
		if err := saveUpload(hdr, destAbs); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		saved++
		wsAudit(r, "upload", "path="+s.wsRel(destAbs)+" bytes="+strconv.FormatInt(hdr.Size, 10))
	}
	writeJSON(w, 200, map[string]any{"uploaded": saved})
}

func saveUpload(hdr *multipart.FileHeader, dest string) error {
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}

// sanitizeFilename strips characters unsafe for a Content-Disposition filename token.
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\"", "")
	name = strings.ReplaceAll(name, "\\", "")
	name = strings.ReplaceAll(name, "\n", "")
	name = strings.ReplaceAll(name, "\r", "")
	return name
}
