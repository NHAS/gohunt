package models

import (
	"strings"

	"github.com/NHAS/gohunt/config"
)

type UIoptions struct {
	Domain    string
	CanSignup bool

	TrustedWebhookDomains string

	SSO bool
}

func UIOptions(c config.Config) UIoptions {
	return UIoptions{
		Domain:    c.Domain,
		CanSignup: c.Features.Signup.Enabled,

		TrustedWebhookDomains: strings.Join(c.Notification.Webhook.SafeDomains, ","),
		SSO:                   c.Features.Oidc.Enabled,
	}
}
