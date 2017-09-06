// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/md5"
	"flag"
	"github.com/intel-go/yanff/flow"
	"github.com/intel-go/yanff/packet"
	"sync"
	"sync/atomic"
	"unsafe"
)

// test-separate-part1: sends packets to 0 port, receives from 0 and 1 ports.
// This part of test generates three packet flows (1st, 2nd and 3rd), merges them into one flow
// and send it to 0 port. Packets in original 1st, 2nd and 3rd flows has UDP destination addresses
// dstPort1, // dstPort2, // dstPort3 respectively. For each packet sender calculates md5 hash sum
// from all headers, write it to packet.Data and check it on packet receive.
// This part of test receive packets on 0 and 1 ports. Expects to get ~33% of packets on 0 port
// (accepted) and ~66% on 1 port (rejected)
// Test also calculates number of broken packets and prints it when a predefined number
// of packets is received.
//
// test-separate-part2:
// This part of test receives packets on 0 port, separate input flow according to rules
// in test-separate-l3rules.conf into 2 flows. Accepted flow sent to 0 port, rejected - to 1 port.

const (
	totalPackets = 100000000

	// Test expects to receive 33% of packets on 0 port and 66% on 1 port
	// Test is PASSSED, if p1 is in [low1;high1] and p2 in [low2;high2]
	eps   = 2
	high1 = 33 + eps
	low1  = 33 - eps
	high2 = 66 + eps
	low2  = 66 - eps
)

var (
	// Payload is 16 byte md5 hash sum of headers
	payloadSize uint   = 16
	speed        uint64 = 1000
	passedLimit uint64 = 85

	recvCount1 uint64
	recvCount2 uint64

	count         uint64
	recvPackets   uint64
	brokenPackets uint64

	dstPort1 uint16 = 111
	dstPort2 uint16 = 222
	dstPort3 uint16 = 333

	testDoneEvent *sync.Cond

	outport uint
	inport1 uint
	inport2 uint
)

func main() {
	flag.UintVar(&outport, "outport", 0, "port for sender")
	flag.UintVar(&inport1, "inport1", 0, "port for 1st receiver")
	flag.UintVar(&inport2, "inport2", 1, "port for 2nd receiver")
	flag.Parse()

	// Init YANFF system at 16 available cores
	config := flow.Config{
		CPUCoresNumber: 16,
	}
	flow.SystemInit(&config)

	var m sync.Mutex
	testDoneEvent = sync.NewCond(&m)

	// Create packet flow
	outputFlow := flow.SetGenerator(generatePacket, speed, nil)
	flow.SetSender(outputFlow, uint8(outport))

	// Create receiving flows and set a checking function for it
	inputFlow1 := flow.SetReceiver(uint8(inport1))
	flow.SetHandler(inputFlow1, checkInputFlow1, nil)

	inputFlow2 := flow.SetReceiver(uint8(inport2))
	flow.SetHandler(inputFlow2, checkInputFlow2, nil)

	flow.SetStopper(inputFlow1)
	flow.SetStopper(inputFlow2)

	// Start pipeline
	go flow.SystemStart()

	// Wait for enough packets to arrive
	testDoneEvent.L.Lock()
	testDoneEvent.Wait()
	testDoneEvent.L.Unlock()

	// Compose statistics
	sent := atomic.LoadUint64(&count)

	recv1 := atomic.LoadUint64(&recvCount1)
	recv2 := atomic.LoadUint64(&recvCount2)
	received := recv1 + recv2

	var p1 int
	var p2 int
	if received != 0 {
		p1 = int(recv1 * 100 / received)
		p2 = int(recv2 * 100 / received)
	}
	broken := atomic.LoadUint64(&brokenPackets)

	// Print report
	println("Sent", sent, "packets")
	println("Received", received, "packets")

	println("On port", inport1, "received=", recv1, "pkts")
	println("On port", inport2, "received=", recv2, "pkts")

	println("Proportion of packets received on", inport1, "port =", p1, "%")
	println("Proportion of packets received on", inport2, "port =", p2, "%")

	println("Broken = ", broken, "packets")

	// Test is PASSSED, if p1 is ~33% and p2 is ~66%
	if p1 <= high1 && p2 <= high2 && p1 >= low1 && p2 >= low2 && received*100/sent > passedLimit {
		println("TEST PASSED")
	} else {
		println("TEST FAILED")
	}

}

func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	if pkt == nil {
		panic("Failed to create new packet")
	}
	atomic.AddUint64(&count, 1)

	if packet.InitEmptyIPv4UDPPacket(pkt, payloadSize) == false {
		panic("Failed to init empty packet")
	}

	// Generate packets of 3 groups
	if count%3 == 0 {
		pkt.UDP.DstPort = packet.SwapBytesUint16(dstPort1)
	} else if count%3 == 1 {
		pkt.UDP.DstPort = packet.SwapBytesUint16(dstPort2)
	} else {
		pkt.UDP.DstPort = packet.SwapBytesUint16(dstPort3)
	}
	headerSize := uintptr(pkt.Data) - pkt.Start()
	hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Start()))[0:headerSize]
	ptr := (*packetData)(pkt.Data)
	ptr.HdrsMD5 = md5.Sum(hdrs)
}

func checkInputFlow1(pkt *packet.Packet, context flow.UserContext) {
	recvCount := atomic.AddUint64(&recvPackets, 1)

	offset := pkt.ParseL4Data()
	if offset < 0 {
		println("ParseL4Data returned negative value", offset)
		// Some received packets are not generated by this example
		// They cannot be parsed due to unknown protocols, skip them
	} else {
		ptr := (*packetData)(pkt.Data)

		// Recompute hash to check how many packets are valid
		headerSize := uintptr(pkt.Data) - pkt.Start()
		hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Start()))[0:headerSize]
		hash := md5.Sum(hdrs)

		if hash != ptr.HdrsMD5 {
			// Packet is broken
			atomic.AddUint64(&brokenPackets, 1)
			return
		}
		atomic.AddUint64(&recvCount1, 1)
	}
	if recvCount >= totalPackets {
		testDoneEvent.Signal()
	}
}

func checkInputFlow2(pkt *packet.Packet, context flow.UserContext) {
	recvCount := atomic.AddUint64(&recvPackets, 1)

	offset := pkt.ParseL4Data()
	if offset < 0 {
		println("ParseL4Data returned negative value", offset)
		// Some received packets are not generated by this example
		// They cannot be parsed due to unknown protocols, skip them
	} else {
		ptr := (*packetData)(pkt.Data)

		// Recompute hash to check how many packets are valid
		headerSize := uintptr(pkt.Data) - pkt.Start()
		hdrs := (*[1000]byte)(unsafe.Pointer(pkt.Start()))[0:headerSize]
		hash := md5.Sum(hdrs)

		if hash != ptr.HdrsMD5 {
			// Packet is broken
			atomic.AddUint64(&brokenPackets, 1)
			return
		}
		atomic.AddUint64(&recvCount2, 1)
	}
	if recvCount >= totalPackets {
		testDoneEvent.Signal()
	}
}

type packetData struct {
	HdrsMD5 [16]byte
}
