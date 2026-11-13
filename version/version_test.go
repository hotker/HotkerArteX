package version

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 版本号"飘"的典型症状：后台显示 2.3.1 而代码已是 2.5.x。根因不是某处写错，
// 而是同一件事散在四个地方各写一遍、发版时总会漏一处。这个测试就是那道闸门：
// 任何一处没跟上，`go test ./version` 立刻变红。
func TestVersionIsSingleSourceOfTruth(t *testing.T) {
	if !semverRe.MatchString(Version) {
		t.Fatalf("Version must be a clean three-part semver (selfupdate 只认可比较的版本号): %q", Version)
	}

	// 1) web/package.json
	pkg := readJSON(t, filepath.Join("..", "web", "package.json"))
	if got := pkg["version"]; got != Version {
		t.Fatalf("web/package.json version = %v, want %s（发版时两处要一起改）", got, Version)
	}

	// 2) web/package-lock.json —— 顶层与 packages[""] 都要一致；npm ci 不会回写它，
	//    这正是"UI/构建产物版本看着旧"的常见来源。
	lock := readJSON(t, filepath.Join("..", "web", "package-lock.json"))
	if got := lock["version"]; got != Version {
		t.Fatalf("web/package-lock.json version = %v, want %s", got, Version)
	}
	if pkgs, ok := lock["packages"].(map[string]any); ok {
		if root, ok := pkgs[""].(map[string]any); ok {
			if got := root["version"]; got != Version {
				t.Fatalf(`web/package-lock.json packages[""].version = %v, want %s`, got, Version)
			}
		}
	}

	// 3) CHANGELOG 的最新条目（第一个 "## [x.y.z]"）必须就是本版本 —— 否则发版说明
	//    与实际二进制对不上。
	log, err := os.ReadFile(filepath.Join("..", "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("read CHANGELOG: %v", err)
	}
	if m := changelogVerRe.FindSubmatch(log); m != nil {
		if got := string(m[1]); got != Version {
			t.Fatalf("CHANGELOG 最新条目是 %s，与 version.Version %s 不一致", got, Version)
		}
	} else {
		t.Fatal("CHANGELOG 里找不到形如 ## [x.y.z] 的版本条目")
	}
}

// 版本号必须是纯净三段式：selfupdate.parseVersion 会把带后缀的版本判为"不可比较"，
// 从而禁用一键更新。这条约束写在测试里，免得有人为了区分构建加了 -rc1 后缀。
func TestVersionIsComparable(t *testing.T) {
	parts := strings.Split(Version, ".")
	if len(parts) != 3 {
		t.Fatalf("want 3 numeric parts, got %d (%q)", len(parts), Version)
	}
	for _, p := range parts {
		if p == "" || !digitsRe.MatchString(p) {
			t.Fatalf("non-numeric version part %q in %q", p, Version)
		}
	}
}

var (
	semverRe       = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	digitsRe       = regexp.MustCompile(`^\d+$`)
	changelogVerRe = regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`)
)

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return out
}
