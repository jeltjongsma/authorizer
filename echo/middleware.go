package echo

import (
	"errors"
	"os"

	"github.com/jeltjongsma/authorizer"
	"github.com/labstack/echo/v4"
)

type MatchMode int

const (
	// MatchAll requires all user roles/permissions to match.
	MatchAll = iota
	// MatchAny requires at least one user role/permission to match.
	MatchAny
)

func userIdFrom(c echo.Context) (int, error) {
	idUnchecked := c.Get(os.Getenv("AUTHORIZER_USER_ID"))
	id, ok := idUnchecked.(int)
	if !ok {
		return 0, errors.New("id missing or not int type")
	}
	return id, nil
}

// AuthorizeRoles takes in an authorizer, a set of roles and a match mode,
// and will abort the request if the user does not meet the role criteria.
func AuthorizeRoles(authorizer authorizer.Authorizer, roles []authorizer.Role, mode MatchMode) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// get user id from context
			id, err := userIdFrom(c)
			if err != nil {
				return echo.NewHTTPError(401, "Unauthorized")
			}

			switch mode {
			// user requires all roles
			case MatchAll:
				for _, r := range roles {
					if decision := authorizer.HasRole(id, r); !decision.Allow {
						return echo.NewHTTPError(403, "Forbidden")
					}
				}
				return next(c)
			// user requires at least one role
			case MatchAny:
				for _, r := range roles {
					if decision := authorizer.HasRole(id, r); decision.Allow {
						return next(c)
					}
				}
				return echo.NewHTTPError(403, "Forbidden")
			default:
				return echo.NewHTTPError(500, "Internal server error")
			}
		}
	}
}

// AuthorizeRoles takes in an authorizer, a set of permissions and a match mode,
// and will abort the request if a user does not meet the permission criteria.
func AuthorizePermissions(authorizer authorizer.Authorizer, permissions []authorizer.Permission, mode MatchMode) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// get user id from context
			id, err := userIdFrom(c)
			if err != nil {
				return echo.NewHTTPError(401, "Unauthorized")
			}

			switch mode {
			// user requires all permissions
			case MatchAll:
				for _, p := range permissions {
					if decision := authorizer.Allow(id, p); !decision.Allow {
						return echo.NewHTTPError(403, "Forbidden")
					}
				}
				return next(c)
			// user requires at least one permission
			case MatchAny:
				for _, p := range permissions {
					if decision := authorizer.Allow(id, p); decision.Allow {
						return next(c)
					}
				}
				return echo.NewHTTPError(403, "Forbidden")
			default:
				return echo.NewHTTPError(500, "Internal server error")
			}
		}
	}
}
