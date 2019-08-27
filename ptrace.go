package tracelib

import (
	"encoding/binary"
	"errors"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// expremental implentation of much faster traceroute
// by sending all packets not one after another but at once

// RunPTrace preforms traceroute to specified host by sending all packets at once
func RunPTrace(host string, source string, source6 string, maxrtt time.Duration, maxttl int, DNScache *LookupCache, rounds int, icmpID int, delay time.Duration) ([][]Hop, error) {

	hops := make([][]Hop, maxttl)
	sendOn := make([][]time.Time, maxttl)
	for i := 0; i < maxttl; i++ {
		hops[i] = make([]Hop, rounds)
		for r := 0; r < rounds; r++ {
			hops[i][r].Timeout = true
		}
		sendOn[i] = make([]time.Time, rounds)
	}

	var (
		conn     net.PacketConn
		ipv4conn *ipv4.PacketConn
		ipv6conn *ipv6.PacketConn
		dest     net.Addr
	)

	var err error
	isIPv6 := false

	addrList, err := net.LookupIP(host)
	if nil != err {
		return nil, err
	}

	for _, addr := range addrList {
		if addr.To4() != nil {
			dest, err = net.ResolveIPAddr("ip4:icmp", addr.String())
			break
		}
	}

	if nil == dest {
		for _, addr := range addrList {
			if addr.To16() != nil {
				isIPv6 = true
				dest, err = net.ResolveIPAddr("ip6:58", addr.String())
				break
			}
		}
	}
	if nil == dest {
		return nil, errors.New("Unable to resolve destination host")
	}

	if nil != err {
		return nil, err
	}

	if !isIPv6 {
		conn, err = net.ListenPacket("ip4:icmp", source)
	} else {
		conn, err = net.ListenPacket("ip6:58", source6)
	}
	if nil != err {
		return nil, err
	}
	defer conn.Close()

	if isIPv6 {
		ipv6conn = ipv6.NewPacketConn(conn)
		defer ipv6conn.Close()
		if err := ipv6conn.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagSrc|ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
			return nil, err
		}
		var f ipv6.ICMPFilter
		f.SetAll(true)
		f.Accept(ipv6.ICMPTypeTimeExceeded)
		f.Accept(ipv6.ICMPTypeEchoReply)
		f.Accept(ipv6.ICMPTypeDestinationUnreachable)
		if err := ipv6conn.SetICMPFilter(&f); err != nil {
			return nil, err
		}
	} else {
		ipv4conn = ipv4.NewPacketConn(conn)
		defer ipv4conn.Close()
	}

	go func() {
		// sending all packets at once
		for i := 1; i <= maxttl; i++ {
			hop := i - 1

			var wcm ipv6.ControlMessage

			if nil != ipv4conn {
				err := ipv4conn.SetTTL(i)
				if nil != err {
					for r := 0; r < rounds; r++ {
						hops[hop][r].Error = err
					}
					continue
				}
			}
			if nil != ipv6conn {
				wcm.HopLimit = i
			}

			for r := 0; r < rounds; r++ {

				var msg icmp.Message

				if isIPv6 {
					msg = icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &icmp.Echo{ID: icmpID, Seq: hop + (maxttl * r)}}
				} else {
					msg = icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: icmpID, Seq: hop + (maxttl * r)}}
				}
				netmsg, err := msg.Marshal(nil)
				if nil != err {
					hops[hop][r].Error = err
					continue
				}

				sendOn[hop][r] = time.Now()

				if nil != ipv4conn {
					_, hops[hop][r].Error = conn.WriteTo(netmsg, dest)
				}
				if nil != ipv6conn {
					_, hops[hop][r].Error = ipv6conn.WriteTo(netmsg, &wcm, dest)
				}

				if 0 != delay {
					time.Sleep(delay)
				}
			}
		}
	}()

	buf := make([]byte, 1500)
	maxSeq := rounds*maxttl - 1

	for mtime := time.Now().Add(maxrtt + (delay * time.Duration(maxSeq))); time.Now().Before(mtime); {
		conn.SetReadDeadline(mtime)

		readLen, addr, err := conn.ReadFrom(buf)

		if nil != err {
			break
		}

		var result *icmp.Message
		if nil != ipv4conn {
			result, err = icmp.ParseMessage(ProtocolICMP, buf[:readLen])
		}
		if nil != ipv6conn {
			result, err = icmp.ParseMessage(ProtocolICMP6, buf[:readLen])
		}
		if nil != err {
			// invalid icmp message
			continue
		}

		switch result.Type {
		case ipv4.ICMPTypeEchoReply:
			if rply, ok := result.Body.(*icmp.Echo); ok {

				if icmpID != rply.ID {
					continue
				}
				if maxSeq < rply.Seq {
					continue
				}

				hops[rply.Seq%maxttl][rply.Seq/maxttl].Addr = addr
				hops[rply.Seq%maxttl][rply.Seq/maxttl].RTT = time.Since(sendOn[rply.Seq%maxttl][rply.Seq/maxttl])
				hops[rply.Seq%maxttl][rply.Seq/maxttl].Final = true
				hops[rply.Seq%maxttl][rply.Seq/maxttl].Timeout = false
			}
		case ipv4.ICMPTypeTimeExceeded:
			if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
				if len(rply.Data) > 26 {
					if uint16(icmpID) != binary.BigEndian.Uint16(rply.Data[24:26]) {
						continue
					}

					seq := int(binary.BigEndian.Uint16(rply.Data[26:28]))
					if maxSeq < seq {
						continue
					}

					hops[seq%maxttl][seq/maxttl].Addr = addr
					hops[seq%maxttl][seq/maxttl].RTT = time.Since(sendOn[seq%maxttl][seq/maxttl])
					hops[seq%maxttl][seq/maxttl].Timeout = false
				}
			}
		case ipv6.ICMPTypeTimeExceeded:
			if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
				if len(rply.Data) > 46 {
					if uint16(icmpID) != binary.BigEndian.Uint16(rply.Data[44:46]) {
						continue
					}

					seq := int(binary.BigEndian.Uint16(rply.Data[26:28]))
					if maxSeq < seq {
						continue
					}

					hops[seq%maxttl][seq/maxttl].Addr = addr
					hops[seq%maxttl][seq/maxttl].RTT = time.Since(sendOn[seq%maxttl][seq/maxttl])
					hops[seq%maxttl][seq/maxttl].Timeout = false
				}
			}
		case ipv6.ICMPTypeEchoReply:
			if rply, ok := result.Body.(*icmp.Echo); ok {
				if icmpID != rply.ID {
					continue
				}
				if maxSeq < rply.Seq {
					continue
				}

				hops[rply.Seq%maxttl][rply.Seq/maxttl].Addr = addr
				hops[rply.Seq%maxttl][rply.Seq/maxttl].RTT = time.Since(sendOn[rply.Seq%maxttl][rply.Seq/maxttl])
				hops[rply.Seq%maxttl][rply.Seq/maxttl].Final = true
				hops[rply.Seq%maxttl][rply.Seq/maxttl].Timeout = false
			}
		case ipv6.ICMPTypeDestinationUnreachable:
			if rply, ok := result.Body.(*icmp.Echo); ok {
				if icmpID != rply.ID {
					continue
				}
				if maxSeq < rply.Seq {
					continue
				}

				hops[rply.Seq%maxttl][rply.Seq/maxttl].Addr = addr
				hops[rply.Seq%maxttl][rply.Seq/maxttl].RTT = time.Since(sendOn[rply.Seq%maxttl][rply.Seq/maxttl])
				hops[rply.Seq%maxttl][rply.Seq/maxttl].Down = true
				hops[rply.Seq%maxttl][rply.Seq/maxttl].Timeout = false
			}
		case ipv4.ICMPTypeDestinationUnreachable:
			if rply, ok := result.Body.(*icmp.Echo); ok {
				if icmpID != rply.ID {
					continue
				}
				if maxSeq < rply.Seq {
					continue
				}

				hops[rply.Seq%maxttl][rply.Seq/maxttl].Addr = addr
				hops[rply.Seq%maxttl][rply.Seq/maxttl].RTT = time.Since(sendOn[rply.Seq%maxttl][rply.Seq/maxttl])
				hops[rply.Seq%maxttl][rply.Seq/maxttl].Down = true
				hops[rply.Seq%maxttl][rply.Seq/maxttl].Timeout = false
			}
		}
	}

	finalHop := maxttl
	for hop := 0; hop < maxttl; hop++ {
		for r := 0; r < rounds; r++ {
			if nil == hops[hop][r].Addr {
				continue
			}
			if nil != DNScache {
				addrString := hops[hop][r].Addr.String()
				hops[hop][r].Host = DNScache.LookupHost(addrString)
				hops[hop][r].AS = DNScache.LookupAS(addrString)
			}
			if maxttl == finalHop && hops[hop][r].Final {
				finalHop = hop + 1
			}

		}
	}

	return hops[:finalHop], nil
}
