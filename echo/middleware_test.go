package echo

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeltjongsma/authorizer"
	"github.com/labstack/echo/v4"
)

func EchoDummy(c echo.Context) error {
	return c.String(200, "OK")
}

func EchoContext() echo.Context {
	e := echo.New()
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func Test_userIdFrom(t *testing.T) {
	tests := []struct {
		inp     any
		wantErr bool
	}{
		{1, false},
		{-1, false},
		{"not an id", true},
	}

	c := EchoContext()

	for _, tt := range tests {
		c.Set("user_id", tt.inp)
		id, err := userIdFrom(c)
		if tt.wantErr {
			if err == nil {
				t.Errorf("expected err, got nil")
			}
		} else {
			if err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
			if id != tt.inp {
				t.Errorf("expected %d, got %d", tt.inp, id)
			}
		}

	}
}

func Test_AuthorizeRoles_MatchAll(t *testing.T) {
	authz := authorizer.InitInMemAuthorizer()

	client := &authorizer.Client{
		App:        "app",
		Authorizer: authz,
		Ttl:        5 * time.Second,
	}

	roleA := client.CreateRole("a")
	roleB := client.CreateRole("b")

	// users need role A and B
	authzRoles := AuthorizeRoles(authz, []authorizer.Role{roleA, roleB}, MatchAll)(EchoDummy)

	c := EchoContext()

	// match both (pass)
	authz.AddRole(0, roleA)
	authz.AddRole(0, roleB)
	c.Set("user_id", 0)

	if err := authzRoles(c); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	// only one match (fail)
	authz.AddRole(1, roleB)
	c.Set("user_id", 1)

	err := authzRoles(c)
	if err == nil {
		t.Fatalf("expected err, got nil")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Errorf("expected HTTP error, got %t", err)
	}

	// expect 403 Forbidden
	if httpErr.Code != 403 {
		t.Errorf("expected 403, got %v", httpErr.Code)
	}

	// none match (fail)
	c.Set("user_id", 2)

	err = authzRoles(c)
	if err == nil {
		t.Fatalf("expected err, got nil")
	}

	httpErr, ok = err.(*echo.HTTPError)
	if !ok {
		t.Errorf("expected HTTP error, got %t", err)
	}

	// expect 403 Forbidden
	if httpErr.Code != 403 {
		t.Errorf("expected 403, got %v", httpErr.Code)
	}
}

func Test_AuthorizeRoles_MatchAny(t *testing.T) {
	authz := authorizer.InitInMemAuthorizer()

	client := &authorizer.Client{
		App:        "app",
		Authorizer: authz,
		Ttl:        5 * time.Second,
	}

	roleA := client.CreateRole("a")
	roleB := client.CreateRole("b")

	// users need role A or B
	authzRoles := AuthorizeRoles(authz, []authorizer.Role{roleA, roleB}, MatchAny)(EchoDummy)

	c := EchoContext()

	// one match (pass)
	authz.AddRole(0, roleA)
	c.Set("user_id", 0)

	if err := authzRoles(c); err != nil {
		t.Fatalf("expected nil , got %v", err)
	}

	// both match (pass)
	authz.AddRole(1, roleA)
	authz.AddRole(1, roleB)
	c.Set("user_id", 1)

	if err := authzRoles(c); err != nil {
		t.Fatalf("expected nil , got %v", err)
	}

	// none match (fail)
	c.Set("user_id", 2)

	err := authzRoles(c)
	if err == nil {
		t.Fatalf("expected err, got nil")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Errorf("expected HTTP error, got %t", err)
	}

	// expect 403 Forbidden
	if httpErr.Code != 403 {
		t.Errorf("expected 403, got %v", httpErr.Code)
	}
}

func Test_AuthorizeRoles_InvalidUserId(t *testing.T) {
	authz := authorizer.InitInMemAuthorizer()

	authzRoles := AuthorizeRoles(authz, []authorizer.Role{}, MatchAny)(EchoDummy)

	c := EchoContext()
	c.Set("user_id", "not an id")

	err := authzRoles(c)
	if err == nil {
		t.Fatalf("expected err, got nil")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Errorf("expected HTTP error, got %t", err)
	}

	// expect 401 Unauthorized
	if httpErr.Code != 401 {
		t.Errorf("expected 401, got %v", httpErr.Code)
	}
}

func Test_AuthorizePermissions_MatchAll(t *testing.T) {
	authz := authorizer.InitInMemAuthorizer()

	client := &authorizer.Client{
		App:        "app",
		Authorizer: authz,
		Ttl:        5 * time.Second,
	}

	permissionA := client.CreatePermission("a", "r")
	permissionB := client.CreatePermission("b", "r")

	// users need permission A and B
	authzRoles := AuthorizePermissions(authz, []authorizer.Permission{permissionA, permissionB}, MatchAll)(EchoDummy)

	c := EchoContext()

	// match both (pass)
	authz.AddPermission(0, permissionA)
	authz.AddPermission(0, permissionB)
	c.Set("user_id", 0)

	if err := authzRoles(c); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	// only one match (fail)
	authz.AddPermission(1, permissionB)
	c.Set("user_id", 1)

	err := authzRoles(c)
	if err == nil {
		t.Fatalf("expected err, got nil")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Errorf("expected HTTP error, got %t", err)
	}

	// expect 403 Forbidden
	if httpErr.Code != 403 {
		t.Errorf("expected 403, got %v", httpErr.Code)
	}

	// none match (fail)
	c.Set("user_id", 2)

	err = authzRoles(c)
	if err == nil {
		t.Fatalf("expected err, got nil")
	}

	httpErr, ok = err.(*echo.HTTPError)
	if !ok {
		t.Errorf("expected HTTP error, got %t", err)
	}

	// expect 403 Forbidden
	if httpErr.Code != 403 {
		t.Errorf("expected 403, got %v", httpErr.Code)
	}
}

func Test_AuthorizePermissions_MatchAny(t *testing.T) {
	authz := authorizer.InitInMemAuthorizer()

	client := &authorizer.Client{
		App:        "app",
		Authorizer: authz,
		Ttl:        5 * time.Second,
	}

	permissionA := client.CreatePermission("a", "r")
	permissionB := client.CreatePermission("b", "r")

	// users need permission A or B
	authzRoles := AuthorizePermissions(authz, []authorizer.Permission{permissionA, permissionB}, MatchAny)(EchoDummy)

	c := EchoContext()

	// match both (pass)
	authz.AddPermission(0, permissionA)
	authz.AddPermission(0, permissionB)
	c.Set("user_id", 0)

	if err := authzRoles(c); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	// one match (pass)
	authz.AddPermission(1, permissionB)
	c.Set("user_id", 1)

	if err := authzRoles(c); err != nil {
		t.Fatalf("expected err, got nil")
	}

	// none match (fail)
	c.Set("user_id", 2)

	err := authzRoles(c)
	if err == nil {
		t.Fatalf("expected err, got nil")
	}

	httpErr, ok := err.(*echo.HTTPError)
	if !ok {
		t.Errorf("expected HTTP error, got %t", err)
	}

	// expect 403 Forbidden
	if httpErr.Code != 403 {
		t.Errorf("expected 403, got %v", httpErr.Code)
	}
}
