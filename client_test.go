package authorizer

import (
	"testing"
	"time"
)

func Test_Client_HasRole(t *testing.T) {
	Authz := &InMemAuthorizer{
		roles:       map[int][]Role{},
		permissions: map[int][]Permission{},
	}

	role := Role{
		App:  "app",
		Role: "role",
	}

	Authz.AddRole(1, role)

	c := &Client{
		App:        "app",
		Authorizer: Authz,
		Ttl:        time.Second * 5,
	}

	decision := c.HasRole(1, "role")
	if !decision.Allow {
		t.Fatalf("expected true, got false")
	}
	if decision.ExpiresIn != time.Second*5 {
		t.Errorf("expected 5 seconds, got %v", decision.ExpiresIn)
	}

	if decision := c.HasRole(1, "not role"); decision.Allow {
		t.Errorf("expected false, got true")
	}

	if decision := c.HasRole(2, "role"); decision.Allow {
		t.Errorf("expected false, got true")
	}
}

func Test_Client_Allow(t *testing.T) {
	Authz := &InMemAuthorizer{
		roles:       map[int][]Role{},
		permissions: map[int][]Permission{},
	}

	permission := Permission{
		App:      "app",
		Action:   "action",
		Resource: "resource",
	}

	Authz.AddPermission(1, permission)

	c := &Client{
		App:        "app",
		Authorizer: Authz,
		Ttl:        time.Second * 5,
	}

	decision := c.Allow(1, "action", "resource")
	if !decision.Allow {
		t.Fatalf("expected true, got false")
	}
	if decision.ExpiresIn != time.Second*5 {
		t.Errorf("expected 5 seconds, got %v", decision.ExpiresIn)
	}

	if decision := c.Allow(1, "not action", "not resource"); decision.Allow {
		t.Errorf("expected false, got true")
	}

	if decision := c.Allow(2, "action", "resource"); decision.Allow {
		t.Errorf("expected false, got true")
	}
}

func Test_Client_CreateRole(t *testing.T) {
	c := &Client{
		App:        "app",
		Authorizer: &InMemAuthorizer{},
		Ttl:        time.Second * 5,
	}

	role := c.CreateRole("role")

	if role.App != "app" || role.Role != "role" {
		t.Errorf("expected 'App role', got %v", role)
	}
}

func Test_Client_CreatePermission(t *testing.T) {
	c := &Client{
		App:        "app",
		Authorizer: &InMemAuthorizer{},
		Ttl:        time.Second * 5,
	}

	permission := c.CreatePermission("action", "resource")

	if permission.App != "app" || permission.Action != "action" || permission.Resource != "resource" {
		t.Errorf("expected 'App action resource' got, %v", permission)
	}
}
