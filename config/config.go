package config

// Config holds the application settings
type Config struct {
	Domain        string `confy_description:"Your gohunt instance domain (add port if not default 443/80)"`
	ListenAddress string `confy_description:"The ip:port combination start the golang http server on"`

	// Used to parse xff
	NumberProxies int `confy_description:"Used to parse X-Forwarded-For"`

	Features struct {
		Signup struct {
			Enabled bool `confy_description:"Enable or disable account creation"`
		}

		Oidc struct {
			Enabled             bool   `confy_description:"Enable or disable OIDC SSO integration"`
			PublicURL           string `confy_description:"URL of Gohunt instance (option can be determined from domain)"`
			IssuerURL           string `confy_description:"Identity provider URL"`
			ClientID            string `confy_description:"OIDC Client ID"`
			ClientSecret        string `confy:";sensitive" confy_description:"OIDC Client Secret"`
			AdminGroupClaimName string `confy_description:"Claim with user groups in it (optional)"`
			AdminGroup          string `confy_description:"Group that indicates user should be administrator of instance (optional)"`
		}
	}

	Notification struct {
		SMTP struct {
			Enabled bool `confy_description:"Enable or disable sending notifications via SMTP"`

			Host      string `confy_description:"Host domain/ip"`
			Port      int    `confy_description:"Port"`
			Username  string `confy_description:"Mailing username"`
			Password  string `confy:";sensitive" confy_description:"Mailing password"`
			FromEmail string `confy_description:"The sending email address"`
		}

		Webhooks struct {
			Enabled     bool     `confy_description:"Enable or disable sending notifications via webhooks"`
			SafeDomains []string `confy_description:"List of domains that are safe to send to, defaults to [discord.com, slack.com]"`
		}

		Confidential bool `confy_description:"Whether to add xss vulnerablity details to notification"`
	}

	Database struct {
		Host     string `confy_description:"Host domain/ip"`
		Port     string `confy_description:"Port"`
		User     string `confy_description:"Database user"`
		DBname   string `confy_description:"Database user password"`
		SSLmode  string `confy_description:"Which database to use"`
		Password string `confy:";sensitive" confy_description:"postgres sslmode"`
	}
}
