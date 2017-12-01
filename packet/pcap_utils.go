// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/intel-go/yanff/common"
	"github.com/intel-go/yanff/low"
)

type nowFuncT func() time.Time

var now nowFuncT = func() time.Time { return time.Now() }

// PcapGlobHdrSize is a size of cap global header.
const PcapGlobHdrSize int64 = 24

// PcapGlobHdr is a Pcap global header.
type PcapGlobHdr struct {
	MagicNumber  uint32 /* magic number */
	VersionMajor uint16 /* major version number */
	VersionMinor uint16 /* minor version number */
	Thiszone     int32  /* GMT to local correction */
	Sigfigs      uint32 /* accuracy of timestamps */
	Snaplen      uint32 /* max length of captured packets, in octets */
	Network      uint32 /* data link type */
}

// PcapRecHdr is a Pcap packet header.
type PcapRecHdr struct {
	TsSec   uint32 /* timestamp seconds */
	TsUsec  uint32 /* timestamp nanoseconds */
	InclLen uint32 /* number of octets of packet saved in file */
	OrigLen uint32 /* actual length of packet */
}

// WritePcapGlobalHdr writes global pcap header into file.
func WritePcapGlobalHdr(f io.Writer) error {
	glHdr := PcapGlobHdr{
		MagicNumber:  0xa1b23c4d, // magic number for nanosecond-resolution pcap file
		VersionMajor: 2,
		VersionMinor: 4,
		Snaplen:      65535,
		Network:      1,
	}
	if err := binary.Write(f, binary.LittleEndian, &glHdr); err != nil {
		common.LogError(common.Debug, "WritePcapGlobalHdr:", err)
		return err
	}
	return nil
}

// WritePcapOnePacket writes one packet with pcap header in file.
// Assumes global pcap header is already present in file. Packet timestamps have nanosecond resolution.
func (pkt *Packet) WritePcapOnePacket(f io.Writer) error {
	bytes := low.GetRawPacketBytesMbuf(pkt.CMbuf)
	if err := writePcapRecHdr(f, bytes); err != nil {
		return err
	}
	return writePacketBytes(f, bytes)
}

func writePcapRecHdr(f io.Writer, pktBytes []byte) error {
	t := now()
	hdr := PcapRecHdr{
		TsSec:   uint32(t.Unix()),
		TsUsec:  uint32(t.UnixNano() % 1e9),
		InclLen: uint32(len(pktBytes)),
		OrigLen: uint32(len(pktBytes)),
	}
	return binary.Write(f, binary.LittleEndian, &hdr)
}

func writePacketBytes(f io.Writer, pktBytes []byte) error {
	if err := binary.Write(f, binary.LittleEndian, pktBytes); err != nil {
		common.LogError(common.Debug, "WritePcapOnePacket internal error:", err)
		return err
	}
	return nil
}

// ReadPcapGlobalHdr read global pcap header into file.
func ReadPcapGlobalHdr(f io.Reader, glHdr *PcapGlobHdr) error {
	if err := binary.Read(f, binary.LittleEndian, glHdr); err != nil {
		common.LogError(common.Debug, "ReadPcapGlobalHdr:", err)
		return err
	}
	return nil
}

func readPcapRecHdr(f io.Reader, hdr *PcapRecHdr) error {
	return binary.Read(f, binary.LittleEndian, hdr)
}

func readPacketBytes(f io.Reader, inclLen uint32) ([]byte, error) {
	pkt := make([]byte, inclLen)
	if err := binary.Read(f, binary.LittleEndian, pkt); err != nil {
		common.LogError(common.Debug, "ReadPcapOnePacket internal error:", err)
		return nil, err
	}
	return pkt, nil
}

// ReadPcapOnePacket read one packet with pcap header from file.
// Assumes that global pcap header is already read.
func (pkt *Packet) ReadPcapOnePacket(f io.Reader) (bool, error) {
	var hdr PcapRecHdr
	if err := readPcapRecHdr(f, &hdr); err == io.EOF {
		return true, nil
	} else if err != nil {
		common.LogError(common.Debug, "ReadPcapOnePacket:", err)
		return false, err
	}
	bytes, err := readPacketBytes(f, hdr.InclLen)
	if err != nil {
		common.LogError(common.Debug, "readPacketBytes:", err)
		return false, err
	}
	GeneratePacketFromByte(pkt, bytes)
	return false, nil
}
