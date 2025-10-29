package authorizer

import "time"

type Role struct {
	App  string
	Role string
}

type Permission struct {
	App      string
	Action   string
	Resource string
}

type Decision struct {
	Allow     bool
	Reason    string
	ExpiresIn time.Duration
}
