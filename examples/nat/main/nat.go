// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/intel-go/yanff/examples/nat"
	"github.com/intel-go/yanff/flow"
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Parse arguments
	cores := flag.String("cores", "0-43", "Specify CPU cores to use")
	configFile := flag.String("config", "config.json", "Specify config file name")
	flag.BoolVar(&nat.CalculateChecksum, "csum", true, "Specify whether to calculate checksums in modified packets")
	flag.BoolVar(&nat.HWTXChecksum, "hwcsum", true, "Specify whether to use hardware offloading for checksums calculation (requires -csum)")
	flag.Parse()

	// Set up reaction to SIGINT (Ctrl-C)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Read config
	CheckFatal(nat.ReadConfig(*configFile))

	// Init YANFF system at 16 available cores
	yanffconfig := flow.Config{
		CPUList:      *cores,
		HWTXChecksum: nat.HWTXChecksum,
	}

	CheckFatal(flow.SystemInit(&yanffconfig))

	// Initialize flows and necessary state
	nat.InitFlows()

	// Start flow scheduler
	go func() {
		CheckFatal(flow.SystemStart())
	}()

	// Wait for interrupt
	sig := <-c
	fmt.Printf("Received signal %v\n", sig)
	nat.CloseAllDumpFiles()
}
