package authorizer

import (
	"fmt"
	"reflect"
	"sync"
)

type IAuthorizer interface {
	HasRole(id int, role Role) *Decision
	Allow(id int, permission Permission) *Decision
}

type InMemAuthorizer struct {
	roles       map[int][]Role
	permissions map[int][]Permission

	mu sync.RWMutex
}

func InitInMemAuthorizer() *InMemAuthorizer {
	return &InMemAuthorizer{
		roles:       map[int][]Role{},
		permissions: map[int][]Permission{},
	}
}

func (authz *InMemAuthorizer) HasRole(id int, role Role) *Decision {
	authz.mu.RLock()
	defer authz.mu.RUnlock()

	if roles, ok := authz.roles[id]; ok {
		for _, r := range roles {
			if reflect.DeepEqual(r, role) {
				return &Decision{
					Allow:  true,
					Reason: fmt.Sprintf("%d has role '%s'", id, role.Role),
				}
			}
		}
	}

	return &Decision{
		Allow:  false,
		Reason: fmt.Sprintf("%d does not have role '%s'", id, role.Role),
	}
}

func (authz *InMemAuthorizer) Allow(id int, permission Permission) *Decision {
	authz.mu.RLock()
	defer authz.mu.RUnlock()

	if permissions, ok := authz.permissions[id]; ok {
		for _, p := range permissions {
			if reflect.DeepEqual(p, permission) {
				return &Decision{
					Allow:  true,
					Reason: fmt.Sprintf("%d can perform '%s' on '%s'", id, permission.Action, permission.Resource),
				}
			}
		}
	}

	return &Decision{
		Allow:  false,
		Reason: fmt.Sprintf("%d can not perform '%s' on '%s'", id, permission.Action, permission.Resource),
	}
}

func (authz *InMemAuthorizer) AddRole(id int, role Role) (added bool) {
	authz.mu.Lock()
	defer authz.mu.Unlock()

	if roles, ok := authz.roles[id]; ok {
		for _, r := range roles {
			if reflect.DeepEqual(r, role) {
				return false
			}
		}
		authz.roles[id] = append(roles, role)
		return true
	}

	authz.roles[id] = []Role{role}
	return true
}

func (authz *InMemAuthorizer) AddPermission(id int, permission Permission) (added bool) {
	authz.mu.Lock()
	defer authz.mu.Unlock()

	if permissions, ok := authz.permissions[id]; ok {
		for _, p := range permissions {
			if reflect.DeepEqual(p, permission) {
				return false
			}
		}
		authz.permissions[id] = append(permissions, permission)
		return true
	}

	authz.permissions[id] = []Permission{permission}
	return true
}
