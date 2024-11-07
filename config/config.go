package config

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"

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

func listFields(v interface{}) []string {
	var fields []string
	t := reflect.TypeOf(v).Elem()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldName := field.Name

		if field.Type.Kind() == reflect.Struct {
			subFields := listFields(reflect.New(field.Type).Interface())
			for _, subField := range subFields {
				fields = append(fields, fmt.Sprintf("%s.%s", fieldName, subField))
			}
		} else {
			fields = append(fields, fieldName)
		}
	}
	return fields
}

func setField(v interface{}, fieldPath string, value string) {
	r := reflect.ValueOf(v).Elem()
	parts := strings.Split(fieldPath, ".")

	for i, part := range parts {
		if i == len(parts)-1 {
			f := r.FieldByName(part)
			if f.IsValid() {
				switch f.Kind() {
				case reflect.Bool:
					f.SetBool(value == "true")
				case reflect.Slice:
					f.Set(reflect.ValueOf(strings.Split(value, ",")))
				case reflect.String:
					f.SetString(value)
				case reflect.Int:

					reflectedVal, err := strconv.Atoi(value)
					if err != nil {
						log.Println(fieldPath, " should be int, but couldnt be parsed as one: ", err)
						continue
					}
					f.SetInt(int64(reflectedVal))

				default:
					log.Printf("Unsupported field type for field: %s", fieldPath)
				}
			} else {
				log.Printf("Field not found: %s", fieldPath)
			}
		} else {
			r = r.FieldByName(part)
		}
	}
}

func LoadConfig(path string) (c Config, err error) {
	c.Notification.Webhooks.SafeDomains = []string{"discord.com", "slack.com"}

	// Load configuration
	configFile, err := os.Open(path)
	if err != nil {

		fields := listFields(&c)
		setSomething := false
		for _, field := range fields {
			envVariable := os.Getenv(field)
			fmt.Printf("%s=%s\n", field, envVariable)

			if envVariable != "" {
				setSomething = true
				setField(&c, field, envVariable)
			}
		}

		if setSomething {
			err = nil
			return
		}

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
