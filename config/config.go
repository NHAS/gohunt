package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// Config holds the application settings
type Config struct {
	Domain        string `yaml:"domain"`
	SMTPHost      string `yaml:"smtp_host"`
	SMTPUsername  string `yaml:"smtp_username"`
	SMTPPassword  string `yaml:"smtp_password"`
	SMTPFromEmail string `yaml:"smtp_from_email"`
	AbuseEmail    string `yaml:"abuse_email"`
	ListenAddress string `yaml:"listen_address"`
	UploadPath    string `yaml:"upload_directory"`

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
