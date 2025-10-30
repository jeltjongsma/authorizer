package authorizer

import (
	"testing"
)

func Test_Client_CreateRole(t *testing.T) {
	c := &Client{
		App: "app",
	}

	role := c.CreateRole("role")

	if role.App != "app" || role.Role != "role" {
		t.Errorf("expected 'app role', got %v", role)
	}
}

func Test_Client_CreatePermission(t *testing.T) {
	c := &Client{
		App: "app",
	}

	permission := c.CreatePermission("action", "resource")

	if permission.App != "app" || permission.Action != "action" || permission.Resource != "resource" {
		t.Errorf("expected 'app action resource' got, %v", permission)
	}
}
