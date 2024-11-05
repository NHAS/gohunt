package main

import (
	"flag"
	"log"

	"github.com/NHAS/gohunt/application"
	"github.com/NHAS/gohunt/config"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Config file for gohunt")

	flag.Parse()

	c, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal("Failed to load config: ", err)
	}

	app, err := application.New(c)
	if err != nil {
		log.Fatal("failed to make new application from config: ", err)
		return
	}

	log.Fatal(app.Run())
}
