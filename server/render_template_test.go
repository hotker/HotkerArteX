package server

import "testing"

// A JSON body whose braces are not placeholders must survive untouched. The
// single-pass scanner used to pair the opening brace of the object with the
// closing brace of the last placeholder, leaving the body unrendered.
func TestRenderTemplateKeepsJSONBraces(t *testing.T) {
	cases := []struct {
		tmpl string
		want string
	}{
		{`{"flag":"{flag}"}`, `{"flag":"CTF{x}"}`},
		{`{"a":{"b":"{v}"}}`, `{"a":{"b":"1"}}`},
		{`{"outer":{"inner":"{v}"},"tail":"{v}"}`, `{"outer":{"inner":"1"},"tail":"1"}`},
		{`{unknown}`, `{unknown}`},
		{`{{v}}`, `{1}`},
		{`no braces`, `no braces`},
	}
	params := map[string]any{"flag": "CTF{x}", "v": 1}
	for _, c := range cases {
		if got := renderTemplate(c.tmpl, params, identity); got != c.want {
			t.Fatalf("renderTemplate(%q) = %q, want %q", c.tmpl, got, c.want)
		}
	}
}

// A value that itself contains a placeholder must not be expanded again: that is
// the prompt-injection-to-command-injection path the single pass closes.
func TestRenderTemplateDoesNotReexpandValues(t *testing.T) {
	params := map[string]any{"a": "{b}", "b": "pwned"}
	if got := renderTemplate("x={a}", params, identity); got != "x={b}" {
		t.Fatalf("value was re-expanded: %q", got)
	}
	// Longest name wins when two params share a prefix.
	params = map[string]any{"id": "short", "id2": "long"}
	if got := renderTemplate("{id2}", params, identity); got != "long" {
		t.Fatalf("prefix collision: %q", got)
	}
}
