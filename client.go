package authorizer

import "time"

type Client struct {
	App        string
	Authorizer IAuthorizer
	Ttl        time.Duration
}

func (c *Client) HasRole(id int, role string) *Decision {
	r := Role{
		App:  c.App,
		Role: role,
	}

	decision := c.Authorizer.HasRole(id, r)
	decision.ExpiresIn = c.Ttl
	return decision
}

func (c *Client) Allow(id int, action, resource string) *Decision {
	p := Permission{
		App:      c.App,
		Action:   action,
		Resource: resource,
	}

	decision := c.Authorizer.Allow(id, p)
	decision.ExpiresIn = c.Ttl
	return decision
}

func (c *Client) CreateRole(role string) Role {
	return Role{
		App:  c.App,
		Role: role,
	}
}

func (c *Client) CreatePermission(action, resource string) Permission {
	return Permission{
		App:      c.App,
		Action:   action,
		Resource: resource,
	}
}
