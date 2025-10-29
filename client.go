package authorizer

import "time"

type Client struct {
	app        string
	authorizer IAuthorizer
	ttl        time.Duration
}

func (c *Client) HasRole(id int, role string) *Decision {
	r := Role{
		App:  c.app,
		Role: role,
	}

	decision := c.authorizer.HasRole(id, r)
	decision.ExpiresIn = c.ttl
	return decision
}

func (c *Client) Allow(id int, action, resource string) *Decision {
	p := Permission{
		App:      c.app,
		Action:   action,
		Resource: resource,
	}

	decision := c.authorizer.Allow(id, p)
	decision.ExpiresIn = c.ttl
	return decision
}

func (c *Client) CreateRole(role string) Role {
	return Role{
		App:  c.app,
		Role: role,
	}
}

func (c *Client) CreatePermission(action, resource string) Permission {
	return Permission{
		App:      c.app,
		Action:   action,
		Resource: resource,
	}
}
