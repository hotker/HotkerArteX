package server

import "testing"

// 改名为 Foxker 后必须仍认旧用户名 ARTEX：现网可能有脚本 / 书签 / 反代配置写死了旧名，
// 一次改名就让它们全部登不进来，代价远大于多一个别名。大小写也不该成为障碍。
func TestValidLoginUsernameAcceptsBothNames(t *testing.T) {
	ok := []string{"Foxker", "foxker", "FOXKER", "  Foxker  ", "ARTEX", "artex", "Artex"}
	for _, u := range ok {
		if !validLoginUsername(u) {
			t.Fatalf("%q should be accepted", u)
		}
	}
	bad := []string{"", "   ", "admin", "foxker2", "artexx", "fox ker"}
	for _, u := range bad {
		if validLoginUsername(u) {
			t.Fatalf("%q must be rejected", u)
		}
	}
}
