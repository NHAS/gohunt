package models

import "github.com/NHAS/gohunt/config"

type UIoptions struct {
	Domain                string
	CanContact, CanSignup bool

	SSO bool
}

func UIOptions(c config.Config) UIoptions {
	return UIoptions{
		Domain:     c.Domain,
		CanContact: c.Features.Contact.Enabled,
		CanSignup:  c.Features.Signup.Enabled,

		SSO: c.Features.Oidc.Enabled,
	}
}
