package main

import (
	"log"

	"github.com/intel-go/yanff/flow"
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Init YANFF system
	config := flow.Config{}
	CheckFatal(flow.SystemInit(&config))

	initCommonState()

	CheckFatal(flow.SystemStart())
}
