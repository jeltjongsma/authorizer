package authorizer

type Client struct {
	App string
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
