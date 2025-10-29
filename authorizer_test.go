package authorizer

import (
	"reflect"
	"testing"
)

func Test_InMem_Init(t *testing.T) {
	authz := InitInMemAuthorizer()
	if authz.roles == nil || authz.permissions == nil {
		t.Errorf("expected fields initialised, got nil")
	}
}

func Test_InMem_AddRole(t *testing.T) {
	authz := InitInMemAuthorizer()

	role := Role{
		App:  "app",
		Role: "role",
	}

	if !authz.AddRole(1, role) {
		t.Fatalf("expected true, got false")
	}

	if !reflect.DeepEqual(authz.roles[1][0], role) {
		t.Errorf("expected %v, got %v", role, authz.roles[1][0])
	}

	if authz.AddRole(1, role) {
		t.Errorf("expected false, got true")
	}

	if l := len(authz.roles[1]); l != 1 {
		t.Errorf("expected 1, got %d", l)
	}
}

func Test_InMem_AddPermission(t *testing.T) {
	authz := InitInMemAuthorizer()

	permission := Permission{
		App:      "app",
		Action:   "action",
		Resource: "resource",
	}

	if !authz.AddPermission(1, permission) {
		t.Fatalf("expected true, got false")
	}

	if !reflect.DeepEqual(authz.permissions[1][0], permission) {
		t.Errorf("expected %v, got %v", permission, authz.permissions[1][0])
	}

	if authz.AddPermission(1, permission) {
		t.Errorf("expected false, got true")
	}

	if l := len(authz.permissions[1]); l != 1 {
		t.Errorf("expected 1, got %d", l)
	}
}

func Test_InMem_HasRole(t *testing.T) {
	authz := InitInMemAuthorizer()

	role := Role{
		App:  "app",
		Role: "role",
	}

	authz.AddRole(1, role)

	if decision := authz.HasRole(1, role); !decision.Allow {
		t.Errorf("expected true, got false")
	}

	if decision := authz.HasRole(1, Role{}); decision.Allow {
		t.Errorf("expected false, got true")
	}
}

func Test_InMem_Allow(t *testing.T) {
	authz := InitInMemAuthorizer()

	permission := Permission{
		App:      "app",
		Action:   "action",
		Resource: "resource",
	}

	authz.AddPermission(1, permission)

	if decision := authz.Allow(1, permission); !decision.Allow {
		t.Errorf("expected true, got false")
	}

	if decision := authz.Allow(1, Permission{}); decision.Allow {
		t.Errorf("expected false, got true")
	}
}
