package main

import (
	"errors"
	"flag"
	"log"
	"os"

	"github.com/NHAS/confy"
	"github.com/NHAS/gohunt/application"
	"github.com/NHAS/gohunt/config"
)

func main() {

	c, warnings, err := confy.Config[config.Config](
		confy.Defaults("config", "config.yaml"),
		confy.WithStrictParsing(),
	)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			log.Fatal(err)
		}
		return
	}

	for _, warning := range warnings {
		log.Println("recieved warning from while parsing configuration sources: ", warning)
	}

	if len(c.Notification.Webhooks.SafeDomains) == 0 {
		c.Notification.Webhooks.SafeDomains = []string{"discord.com", "slack.com"}
	}

	app, err := application.New(c)
	if err != nil {
		log.Println("failed to make new application from config: ", err)
		os.Exit(1)
		return
	}

	if err := app.Run(); err != nil {
		log.Printf("application failed and had to stop: %s", err)
		os.Exit(1)
		return
	}
}
