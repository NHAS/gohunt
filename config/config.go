package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Config holds the application settings
type Config struct {
	Domain        string `yaml:"domain"`
	ListenAddress string `yaml:"listen_address"`

	// Used to parse xff
	NumberProxies int `yaml:"number_proxies"`

	Features struct {
		Signup struct {
			Enabled bool `yaml:"enabled"`
		}

		Oidc struct {
			Enabled             bool   `yaml:"enabled"`
			PublicURL           string `yaml:"public_url"`
			IssuerURL           string `yaml:"issuer_url"`
			ClientID            string `yaml:"client_id"`
			ClientSecret        string `yaml:"client_secret"`
			AdminGroupClaimName string `yaml:"admin_group_claim_name"`
			AdminGroup          string `yaml:"admin_group_name"`
		}
	}

	Notification struct {
		SMTP struct {
			Enabled bool `yaml:"enabled"`

			Host      string `yaml:"host"`
			Port      int    `yaml:"port"`
			Username  string `yaml:"username"`
			Password  string `yaml:"password"`
			FromEmail string `yaml:"from"`
		}

		Webhooks struct {
			Enabled     bool     `yaml:"enabled"`
			SafeDomains []string `yaml:"safe_domains"`
		}

		Confidential bool `yaml:"confidential"`
	}

	Database struct {
		Host     string `yaml:"host"`
		Port     string `yaml:"port"`
		User     string `yaml:"user"`
		DBname   string `yaml:"dbname"`
		SSLmode  string `yaml:"sslmode"`
		Password string `yaml:"password"`
	}
}

func LoadConfig(path string) (c Config, err error) {

	// Load configuration
	configFile, err := os.Open(path)
	if err != nil {
		err = fmt.Errorf("error reading config.yaml, have you created one? Error: %s", err)
		return
	}
	defer configFile.Close()

	decoder := yaml.NewDecoder(configFile)
	decoder.SetStrict(false)
	err = decoder.Decode(&c)
	if err != nil {
		err = fmt.Errorf("error decoding config: %s", err)
		return
	}

	if len(c.Notification.Webhooks.SafeDomains) == 0 {
		c.Notification.Webhooks.SafeDomains = []string{"discord.com", "slack.com"}
	}

	return
}
