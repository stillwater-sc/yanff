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
	config := flow.Config{}
	CheckFatal(flow.SystemInit(&config))

	initCommonState()

	firstFlow, err := flow.SetReceiver(uint8(0))
	CheckFatal(err)
	CheckFatal(flow.SetHandler(firstFlow, modifyPacket[0], nil))
	CheckFatal(flow.SetSender(firstFlow, uint8(0)))

	CheckFatal(flow.SystemStart())
}
