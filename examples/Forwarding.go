// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"

	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
)

var l3Rules *packet.L3Rules

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// Main function for constructing packet processing graph.
func main() {
	var err error
	// Initialize YANFF library at 16 cores by default
	config := flow.Config{
		CPUList: "0-15",
	}
	CheckFatal(flow.SystemInit(&config))

	// Get splitting rules from access control file.
	l3Rules, err = packet.GetL3ACLFromORIG("Forwarding.conf")
	CheckFatal(err)

	// Receive packets from zero port. Receive queue will be added automatically.
	inputFlow, err := flow.SetReceiver(uint8(0))
	CheckFatal(err)

	// Split packet flow based on ACL.
	flowsNumber := 5
	outputFlows, err := flow.SetSplitter(inputFlow, l3Splitter, uint(flowsNumber), nil)
	CheckFatal(err)

	// "0" flow is used for dropping packets without sending them.
	CheckFatal(flow.SetStopper(outputFlows[0]))

	// Send each flow to corresponding port. Send queues will be added automatically.
	for i := 1; i < flowsNumber; i++ {
		CheckFatal(flow.SetSender(outputFlows[i], uint8(i-1)))
	}

	// Begin to process packets.
	CheckFatal(flow.SystemStart())
}

// User defined function for splitting packets
func l3Splitter(currentPacket *packet.Packet, context flow.UserContext) uint {
	// Return number of flow to which put this packet. Based on ACL rules.
	return currentPacket.L3ACLPort(l3Rules)
}
