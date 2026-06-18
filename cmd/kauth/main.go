package main

import (
	"fmt"
	"log"

	"github.com/zral/kauth-go/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("kauth starter på port %s\n", cfg.HTTPPort)
}
