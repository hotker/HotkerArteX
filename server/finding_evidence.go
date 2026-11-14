package server

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
	"github.com/Autumn-27/artex/report"
)

// 漏洞证据截图的上传 / 列表 / 编辑 / 删除 / 取图。
//
// 安全基线（这本身是安全平台，上传点不能成为恶意文件入口）：
//   - 不信任扩展名与客户端 MIME：按内容识别类型 + 完整解码 + **重编码**后再落盘。
//     重编码会剥掉尾部追加内容、EXIF（含 GPS）、polyglot 结构 —— "校验通过就存"做不到这一点；
//   - 先用 DecodeConfig 看尺寸再整幅解码，挡解压炸弹；
//   - 取图响应固定图片 Content-Type + nosniff + inline：即使磁盘文件被篡改，
//     浏览器也不会当 HTML/脚本执行。
//
// 存储布局：<dataDir>/evidence/<finding_id>/<name>。与库行一一对应，删行即删文件。

// evidenceDir 返回某漏洞的截图目录。
func (s *Server) evidenceDir(findingID int64) string {
	return filepath.Join(s.m.dir, "evidence", strconv.FormatInt(findingID, 10))
}

// evidenceURL 构造前端取图 URL（浏览器 <img> 无法带 Authorization，走 cookie）。
func evidenceURL(findingID int64, filename string) string {
	return fmt.Sprintf("/api/findings/%d/evidence/%s", findingID, filename)
}

// POST /api/findings/{id}/evidence — multipart: file + 可选 caption / step_index。
func (s *Server) uploadFindingEvidence(w http.ResponseWriter, r *http.Request) {
	findingID := pathIntOr(r, "id")
	if findingID <= 0 {
		writeErr(w, 400, "无效的漏洞 id")
		return
	}
	f, err := s.m.pg.GetFinding(findingID)
	if err != nil || f == nil {
		writeErr(w, 404, "未找到漏洞")
		return
	}
	if err := r.ParseMultipartForm(evidence.MaxBytes + (1 << 20)); err != nil {
		writeErr(w, 400, "上传解析失败")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, "缺少文件")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, evidence.MaxBytes+1))
	if err != nil {
		writeErr(w, 400, "读取失败")
		return
	}
	clean, ext, wid, hei, err := evidence.Sanitize(raw)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}

	dir := s.evidenceDir(findingID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, 500, "创建目录失败")
		return
	}
	base := fmt.Sprintf("ev-%d", time.Now().UnixNano())
	name := base + ext
	if err := os.WriteFile(filepath.Join(dir, name), clean, 0o644); err != nil {
		writeErr(w, 500, "写入失败")
		return
	}

	step := atoiDefault(r.FormValue("step_index"), 0)
	caption := strings.TrimSpace(r.FormValue("caption"))
	if caption == "" {
		// 图注自动派生：没手填就用该步复现文案（agent 记录的"证明了什么"），
		// 不额外调 LLM —— 图注的作用是让人对照，不是文学创作。
		caption = deriveEvidenceCaption(f, step)
	}
	if caption == "" {
		caption = strings.TrimSuffix(hdr.Filename, filepath.Ext(hdr.Filename))
	}
	ev, err := s.m.pg.CreateFindingEvidence(findingID, name, caption, step, wid, hei, int64(len(clean)))
	if err != nil {
		_ = os.Remove(filepath.Join(dir, name)) // 落库失败就别留孤儿文件
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	s.auditFrom(r, "", "finding", "upload_evidence", "success",
		fmt.Sprintf("为漏洞 #%d 上传证据截图 %s", findingID, name), map[string]any{"finding_id": findingID, "size": len(clean)})
	writeJSON(w, 200, map[string]any{"evidence": ev, "url": evidenceURL(findingID, name)})
}

// deriveEvidenceCaption 由该步的复现文案派生一句图注（"步骤N：证明了什么"）。
func deriveEvidenceCaption(f *db.DBFinding, step int) string {
	if f == nil || f.Reproduction == nil || step <= 0 || step > len(f.Reproduction.Steps) {
		return ""
	}
	st := f.Reproduction.Steps[step-1]
	text := strings.TrimSpace(st.Proves)
	if text == "" {
		text = strings.TrimSpace(st.Expected)
	}
	if text == "" {
		return ""
	}
	if i := strings.IndexByte(text, '\n'); i > 0 {
		text = text[:i] // 图注一行就够
	}
	r := []rune(text)
	if len(r) > 100 {
		text = string(r[:100]) + "…"
	}
	return fmt.Sprintf("步骤%d：%s", step, text)
}

// GET /api/findings/{id}/evidence — 列出全部截图。
func (s *Server) listFindingEvidence(w http.ResponseWriter, r *http.Request) {
	findingID := pathIntOr(r, "id")
	if findingID <= 0 {
		writeErr(w, 400, "无效的漏洞 id")
		return
	}
	list, err := s.m.pg.ListFindingEvidence(findingID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		out = append(out, map[string]any{"evidence": e, "url": evidenceURL(findingID, e.Filename)})
	}
	writeJSON(w, 200, map[string]any{"items": out})
}

// PUT /api/findings/{id}/evidence/{eid} — 改图注 / 所属步骤 / 排序。
func (s *Server) updateFindingEvidence(w http.ResponseWriter, r *http.Request) {
	eid := pathIntOr(r, "eid")
	if eid <= 0 {
		writeErr(w, 400, "无效的证据 id")
		return
	}
	var req struct {
		Caption   string `json:"caption"`
		StepIndex *int   `json:"step_index"`
		SortOrder int    `json:"sort_order"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	step := -1 // -1 = 不改（SQL 里用 CASE 判断）
	if req.StepIndex != nil {
		step = *req.StepIndex
	}
	if err := s.m.pg.UpdateFindingEvidence(eid, req.Caption, step, req.SortOrder); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// DELETE /api/findings/{id}/evidence/{eid}
func (s *Server) deleteFindingEvidence(w http.ResponseWriter, r *http.Request) {
	findingID := pathIntOr(r, "id")
	eid := pathIntOr(r, "eid")
	if eid <= 0 {
		writeErr(w, 400, "无效的证据 id")
		return
	}
	ev, err := s.m.pg.DeleteFindingEvidence(eid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if ev == nil {
		writeErr(w, 404, "证据不存在")
		return
	}
	_ = os.Remove(filepath.Join(s.evidenceDir(findingID), filepath.Base(ev.Filename)))
	s.auditFrom(r, "", "finding", "delete_evidence", "success", "删除证据截图 "+ev.Filename, map[string]any{"finding_id": findingID})
	writeJSON(w, 200, map[string]any{"deleted": eid})
}

// GET /api/findings/{id}/evidence/{file} — 取图。
//
// 用 filepath.Base 防路径穿越；Content-Type 由扩展名写死（不接受任何来自文件内容的分歧），
// 加 nosniff 与 inline —— 三道一起才挡得住"把 HTML 塞进图片扩展名"的存储型 XSS。
func (s *Server) serveFindingEvidence(w http.ResponseWriter, r *http.Request) {
	findingID := pathIntOr(r, "id")
	if findingID <= 0 {
		writeErr(w, 400, "无效的漏洞 id")
		return
	}
	file := filepath.Base(r.PathValue("file"))
	if !filepath.IsLocal(file) || strings.Contains(file, "..") {
		writeErr(w, 400, "非法文件名")
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch strings.ToLower(filepath.Ext(file)) {
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".jpg", ".jpeg":
		w.Header().Set("Content-Type", "image/jpeg")
	default:
		writeErr(w, 404, "not found")
		return
	}
	w.Header().Set("Content-Disposition", "inline")
	full := filepath.Join(s.evidenceDir(findingID), file)
	if _, err := os.Stat(full); err != nil {
		writeErr(w, 404, "文件不存在")
		return
	}
	http.ServeFile(w, r, full)
}

// reportImagesFor 取报告要用的截图（已转成 report.Image）。
// 读不到文件不算错：截图丢失不该让整份报告生成失败 —— 报告里少一张图比出不来好。
func (s *Server) reportImagesFor(findingID int64) []report.Image {
	list, err := s.m.pg.ListFindingEvidence(findingID)
	if err != nil || len(list) == 0 {
		return nil
	}
	out := make([]report.Image, 0, len(list))
	for _, e := range list {
		raw, err := os.ReadFile(filepath.Join(s.evidenceDir(findingID), filepath.Base(e.Filename)))
		if err != nil {
			continue
		}
		ext := ".png"
		if strings.EqualFold(filepath.Ext(e.Filename), ".jpg") {
			ext = ".jpg"
		}
		out = append(out, report.Image{
			Bytes: raw, Ext: ext, Width: e.Width, Height: e.Height,
			Caption: e.Caption, StepIndex: e.StepIndex,
		})
	}
	return out
}
