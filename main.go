package main

import (
	"log"

	"github.com/harshgupta9473/friends/components"
)

func main() {
	store, err := components.NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}
	err = store.Init()
	if err != nil {
		log.Fatal(err)
	}
	server := components.NewServer(":3000", store)
	server.Run()

}
