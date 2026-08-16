package proxy

import "testing"

func TestSplitPath(t *testing.T) {
	cases := []struct {
		path                  string
		tenant, service, rest string
	}{
		{"/t/acme/s/demo/mcp", "acme", "demo", "/mcp"},
		{"/t/acme/s/demo", "acme", "demo", "/"},
		{"/t/acme/s/demo/a/b/c", "acme", "demo", "/a/b/c"},
		{"/t/acme/x/demo", "", "", ""},
		{"/t/acme", "", "", ""},
		{"/other/acme/s/demo", "", "", ""},
		{"/", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			tenant, service, rest := splitPath(tc.path)
			if tenant != tc.tenant || service != tc.service || rest != tc.rest {
				t.Errorf("splitPath(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tc.path, tenant, service, rest, tc.tenant, tc.service, tc.rest)
			}
		})
	}
}
