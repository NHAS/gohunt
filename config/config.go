package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Config holds the application settings
type Config struct {
	Domain        string `yaml:"domain"`
	AbuseEmail    string `yaml:"abuse_email"`
	ListenAddress string `yaml:"listen_address"`

	Notification struct {
		SMTP struct {
			Enabled bool `yaml:"enabled"`

			Host      string `yaml:"host"`
			Port      int    `yaml:"port"`
			Username  string `yaml:"username"`
			Password  string `yaml:"password"`
			FromEmail string `yaml:"from"`
		}

		Confidential bool `"yaml:confidential"`
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

	return
}
