package intercept

import "testing"

// IsForcedTool must gate the self-service tools and every MCP tool, but leave
// ordinary tools alone.
func TestIsForcedTool(t *testing.T) {
	forced := []string{
		"create_skill", "update_skill_file",
		"create_custom_tool", "update_custom_tool",
		"create_mcp", "update_mcp",
		"delete_assets_by_host",
		"mcp__browser__navigate",
		"mcp__anything__tool",
	}
	for _, name := range forced {
		if !IsForcedTool(name) {
			t.Errorf("IsForcedTool(%q) = false, want true", name)
		}
	}
	ordinary := []string{
		"Bash", "WebFetch", "Write", "Edit", "MultiEdit",
		"web_search", "shell_open", "shell_send",
		"my_custom_tool", // a custom tool by name is NOT in the forced set
		"mcpfoo",         // near-miss prefix must not match
		"",
	}
	for _, name := range ordinary {
		if IsForcedTool(name) {
			t.Errorf("IsForcedTool(%q) = true, want false", name)
		}
	}
}

// The gate must not be defeatable: a forced tool enters the rule system even when
// the enabled-tools set is empty (the "clear the whole list" bypass is closed).
// An empty non-nil map is exactly the state left after a user clears the list via
// SetEnabledTools, and it short-circuits before any database access.
func TestIsToolEnabledForcedBypassesEmptyList(t *testing.T) {
	i := New(nil)
	i.enabledTools = map[string]bool{} // user cleared the whole list
	// An ordinary tool is not enabled.
	if i.IsToolEnabled("Bash") {
		t.Fatal("ordinary tool enabled with empty list, want false")
	}
	// But the forced self-service and MCP tools are always enabled.
	for _, name := range []string{"create_mcp", "create_custom_tool", "mcp__s__t", "delete_assets_by_host"} {
		if !i.IsToolEnabled(name) {
			t.Errorf("IsToolEnabled(%q) = false, want true (forced gate)", name)
		}
	}
}
