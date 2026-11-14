package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func testPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{B: 255, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// multipart 打包一次上传请求。
func multipartUpload(t *testing.T, path string, token string, file []byte, filename string, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(file)
	_ = mw.Close()
	req := httptest.NewRequest("POST", path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	_ = req
	return w
}

// 上传 → 列表 → 取图 → 删除，走真实 handler；并验证文件真的落盘又在删除时清掉。
func TestEvidenceUploadListServeDelete(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, err := pg.CreateTask("证据测试", "", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	f := seedFinding(t, s, task.ID, "带截图的漏洞")
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID) })

	// 关联复现步骤，用来验证图注自动派生
	if _, err := pg.SetFindingReproduction(f.ID, &db.Reproduction{
		Steps: []db.ReproStep{{Request: "POST /a", Response: "HTTP 200", Proves: "成功绕过登录"}},
	}); err != nil {
		t.Fatalf("set reproduction: %v", err)
	}

	// --- upload ---
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("step_index", "1")
	fw, _ := mw.CreateFormFile("file", "shot.png")
	_, _ = fw.Write(testPNG(t, 400, 200))
	_ = mw.Close()
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/findings/%d/evidence", f.ID), &body)
	req.SetPathValue("id", fmt.Sprint(f.ID))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	s.uploadFindingEvidence(rec, req)
	if rec.Code != 200 {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	var up struct {
		Evidence db.FindingEvidence `json:"evidence"`
		URL      string             `json:"url"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &up)
	if up.Evidence.ID == 0 || !strings.HasSuffix(up.Evidence.Filename, ".png") {
		t.Fatalf("bad upload result: %+v", up.Evidence)
	}
	if up.Evidence.Width != 400 || up.Evidence.Height != 200 {
		t.Fatalf("size not recorded: %dx%d", up.Evidence.Width, up.Evidence.Height)
	}
	// 图注从复现步骤派生
	if !strings.Contains(up.Evidence.Caption, "成功绕过登录") {
		t.Fatalf("caption should derive from the reproduction step, got %q", up.Evidence.Caption)
	}
	onDisk := filepath.Join(s.evidenceDir(f.ID), up.Evidence.Filename)
	if _, err := os.Stat(onDisk); err != nil {
		t.Fatalf("file not written: %v", err)
	}

	// --- list ---
	req = httptest.NewRequest("GET", fmt.Sprintf("/api/findings/%d/evidence", f.ID), nil)
	req.SetPathValue("id", fmt.Sprint(f.ID))
	rec = httptest.NewRecorder()
	s.listFindingEvidence(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), up.Evidence.Filename) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}

	// --- serve ---
	req = httptest.NewRequest("GET", fmt.Sprintf("/api/findings/%d/evidence/%s", f.ID, up.Evidence.Filename), nil)
	req.SetPathValue("id", fmt.Sprint(f.ID))
	req.SetPathValue("file", up.Evidence.Filename)
	rec = httptest.NewRecorder()
	s.serveFindingEvidence(rec, req)
	if rec.Code != 200 {
		t.Fatalf("serve: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("content-type = %q, want image/png", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("nosniff header missing")
	}

	// 路径穿越：../ 必须被挡下
	req = httptest.NewRequest("GET", "/api/findings/1/evidence/..%2f..%2fetc%2fpasswd", nil)
	req.SetPathValue("id", "1")
	req.SetPathValue("file", "../../etc/passwd")
	rec = httptest.NewRecorder()
	s.serveFindingEvidence(rec, req)
	if rec.Code == 200 {
		t.Fatal("path traversal should be rejected")
	}

	// --- delete ---
	req = httptest.NewRequest("DELETE", fmt.Sprintf("/api/findings/%d/evidence/%d", f.ID, up.Evidence.ID), nil)
	req.SetPathValue("id", fmt.Sprint(f.ID))
	req.SetPathValue("eid", fmt.Sprint(up.Evidence.ID))
	rec = httptest.NewRecorder()
	s.deleteFindingEvidence(rec, req)
	if rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(onDisk); !os.IsNotExist(err) {
		t.Fatal("file should be removed with the row")
	}
}

// 非图片内容一律拒绝（这是安全平台的上传点，不能成为恶意文件入口）。
func TestEvidenceRejectsNonImage(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, _ := pg.CreateTask("证据拒绝", "", nil, 0, 0)
	f := seedFinding(t, s, task.ID, "x")
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID) })

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "evil.png")
	_, _ = fw.Write([]byte("<html><script>alert(1)</script></html>"))
	_ = mw.Close()
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/findings/%d/evidence", f.ID), &body)
	req.SetPathValue("id", fmt.Sprint(f.ID))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	s.uploadFindingEvidence(rec, req)
	if rec.Code != 400 {
		t.Fatalf("non-image must be rejected, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "png/jpg/gif") {
		t.Fatalf("error should explain what's supported: %s", rec.Body.String())
	}
}

// 报告装配必须把截图按 step_index 分组带出去。
func TestReportImagesAttachByStep(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.pg
	task, _ := pg.CreateTask("证据进报告", "", nil, 0, 0)
	f := seedFinding(t, s, task.ID, "有图的漏洞")
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM findings WHERE task_id=$1`, task.ID) })

	dir := s.evidenceDir(f.ID)
	_ = os.MkdirAll(dir, 0o755)
	for i, step := range []int{0, 1} {
		name := fmt.Sprintf("ev-%d.png", i)
		_ = os.WriteFile(filepath.Join(dir, name), testPNG(t, 100, 50), 0o644)
		if _, err := pg.CreateFindingEvidence(f.ID, name, fmt.Sprintf("图注%d", step), step, 100, 50, 100); err != nil {
			t.Fatalf("create evidence: %v", err)
		}
	}
	f2, _ := pg.GetFinding(f.ID)
	rf := s.toReportFindings([]*db.DBFinding{f2})
	if len(rf[0].Images) != 2 {
		t.Fatalf("expected 2 images in report finding, got %d", len(rf[0].Images))
	}
	steps := map[int]int{}
	for _, im := range rf[0].Images {
		steps[im.StepIndex]++
		if len(im.Bytes) == 0 {
			t.Fatal("image bytes not loaded")
		}
	}
	if steps[1] != 1 || steps[0] != 1 {
		t.Fatalf("step attribution lost: %v", steps)
	}
	_ = http.MethodGet
}
