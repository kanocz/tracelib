package tracelib

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
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

// RunMPTrace preforms traceroute to many hosts by sending all packets at once using one (or 2) raw socket(s)
func RunMPTrace(hosts []string, source string, source6 string, maxrtt time.Duration, maxttl int, DNScache *LookupCache, rounds int, startIcmpID int, delay time.Duration) (map[string]*[][]Hop, error) {

	hops := make(map[string]*[][]Hop, len(hosts))
	sendOn := make(map[string]*[][]time.Time, len(hosts))
	isIPv6 := make(map[string]bool, len(hosts))
	dest := make(map[string]net.Addr, len(hosts))
	addrs := make(map[string]string, len(hosts))
	addrsb := make(map[string][]byte, len(hosts))

	for _, host := range hosts {

		_hops := make([][]Hop, maxttl)
		_sendOn := make([][]time.Time, maxttl)
		hops[host] = &_hops
		sendOn[host] = &_sendOn

		for i := 0; i < maxttl; i++ {
			_hops[i] = make([]Hop, rounds)
			for r := 0; r < rounds; r++ {
				_hops[i][r].Timeout = true
			}
			_sendOn[i] = make([]time.Time, rounds)
		}
	}

	var (
		conn4    net.PacketConn
		conn6    net.PacketConn
		ipv4conn *ipv4.PacketConn
		ipv6conn *ipv6.PacketConn
	)

	var err error

	hasIPv4 := false
	hasIPv6 := false

	for _, host := range hosts {

		addrList, err := net.LookupIP(host)
		if nil != err {
			return nil, err
		}

		for _, addr := range addrList {
			if addr.To4() != nil {
				dest[host], err = net.ResolveIPAddr("ip4:icmp", addr.String())
				addrs[addr.String()] = host
				addrsb[host] = []byte(addr.To16())
				hasIPv4 = true
				break
			}
		}

		if nil == dest[host] {
			for _, addr := range addrList {
				if addr.To16() != nil {
					isIPv6[host] = true
					dest[host], err = net.ResolveIPAddr("ip6:58", addr.String())
					addrs[addr.String()] = host
					addrsb[host] = []byte(addr.To16())
					hasIPv6 = true
					break
				}
			}
		}

		if nil == dest[host] {
			return nil, errors.New("Unable to resolve destination host for " + host)
		}

		if nil != err {
			return nil, err
		}

	}

	if hasIPv4 {
		conn4, err = net.ListenPacket("ip4:icmp", source)
		if nil != err {
			return nil, err
		}
		defer conn4.Close()

		ipv4conn = ipv4.NewPacketConn(conn4)
		defer ipv4conn.Close()
	}

	if hasIPv6 {
		conn6, err = net.ListenPacket("ip6:58", source6)
		if nil != err {
			return nil, err
		}
		defer conn6.Close()

		ipv6conn = ipv6.NewPacketConn(conn6)
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
	}

	go func() {

		// sending all packets at once... grouped not by hosts, but by ttl :)
		for i := 1; i <= maxttl; i++ {

			hop := i - 1

			var wcm ipv6.ControlMessage

			if nil != ipv4conn {
				err := ipv4conn.SetTTL(i)
				if nil != err {
					for r := 0; r < rounds; r++ {
						for _, host := range hosts {
							if !isIPv6[host] {
								(*hops[host])[hop][r].Error = err
							}
						}
					}
					continue
				}
			}
			if nil != ipv6conn {
				wcm.HopLimit = i
			}

			for r := 0; r < rounds; r++ {

				for hostid, host := range hosts {

					var icmpType icmp.Type

					if isIPv6[host] {
						icmpType = ipv6.ICMPTypeEchoRequest
					} else {
						icmpType = ipv4.ICMPTypeEcho
					}

					msg := icmp.Message{Type: icmpType, Code: 0, Body: &icmp.Echo{ID: startIcmpID + hostid, Seq: hop + (maxttl * r), Data: addrsb[host]}}
					netmsg, err := msg.Marshal(nil)
					if nil != err {
						for _, host := range hosts {
							if !isIPv6[host] {
								(*hops[host])[hop][r].Error = err
							}
						}
						continue
					}

					(*sendOn[host])[hop][r] = time.Now()

					if isIPv6[host] {
						_, (*hops[host])[hop][r].Error = ipv6conn.WriteTo(netmsg, &wcm, dest[host])
					} else {
						_, (*hops[host])[hop][r].Error = conn4.WriteTo(netmsg, dest[host])
					}

					if 0 != delay {
						time.Sleep(delay)
					}

				}

			}
		}
	}()

	maxSeq := rounds*maxttl - 1

	var wg sync.WaitGroup

	// we have up to 2 sockets, so need 2 separate conn.ReadFrom threads

	maxICMPid := startIcmpID + len(hosts) - 1

	if hasIPv4 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			buf := make([]byte, 1500)

			for mtime := time.Now().Add(maxrtt + (delay * time.Duration(maxSeq))); time.Now().Before(mtime); {

				conn4.SetReadDeadline(mtime)
				readLen, addr, err := conn4.ReadFrom(buf)
				if nil != err {
					break
				}

				result, err := icmp.ParseMessage(ProtocolICMP, buf[:readLen])
				if nil != err {
					continue // invalid icmp message
				}

				switch result.Type {
				case ipv4.ICMPTypeEchoReply:
					if rply, ok := result.Body.(*icmp.Echo); ok {

						if rply.ID < startIcmpID || rply.ID > maxICMPid {
							continue
						}
						if maxSeq < rply.Seq {
							continue
						}

						hopS := (*hops[hosts[rply.ID-startIcmpID]])
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Addr = addr
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].RTT = time.Since((*sendOn[hosts[rply.ID-startIcmpID]])[rply.Seq%maxttl][rply.Seq/maxttl])
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Final = true
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Timeout = false
					}
				case ipv4.ICMPTypeTimeExceeded:
					if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
						if len(rply.Data) > 26 {
							id := int(binary.BigEndian.Uint16(rply.Data[24:26]))
							if id < startIcmpID || id > maxICMPid {
								continue
							}

							seq := int(binary.BigEndian.Uint16(rply.Data[26:28]))
							if maxSeq < seq {
								continue
							}

							hopS := (*hops[hosts[id-startIcmpID]])
							hopS[seq%maxttl][seq/maxttl].Addr = addr
							hopS[seq%maxttl][seq/maxttl].RTT = time.Since((*sendOn[hosts[id-startIcmpID]])[seq%maxttl][seq/maxttl])
							hopS[seq%maxttl][seq/maxttl].Timeout = false
						}
					}
				case ipv4.ICMPTypeDestinationUnreachable:
					if rply, ok := result.Body.(*icmp.Echo); ok {
						if rply.ID < startIcmpID || rply.ID > maxICMPid {
							continue
						}
						if maxSeq < rply.Seq {
							continue
						}

						hopS := (*hops[hosts[rply.ID-startIcmpID]])
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Addr = addr
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].RTT = time.Since((*sendOn[hosts[rply.ID-startIcmpID]])[rply.Seq%maxttl][rply.Seq/maxttl])
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Down = true
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Timeout = false
					}
				}
			}

		}()
	}

	if hasIPv6 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			buf := make([]byte, 1500)

			for mtime := time.Now().Add(maxrtt + (delay * time.Duration(maxSeq))); time.Now().Before(mtime); {

				conn6.SetReadDeadline(mtime)
				readLen, addr, err := conn6.ReadFrom(buf)

				if nil != err {
					break
				}

				result, err := icmp.ParseMessage(ProtocolICMP6, buf[:readLen])
				if nil != err {
					continue // invalid icmp message
				}

				switch result.Type {
				case ipv6.ICMPTypeTimeExceeded:
					if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
						if len(rply.Data) > 46 {

							id := int(binary.BigEndian.Uint16(rply.Data[44:46]))
							seq := int(binary.BigEndian.Uint16(rply.Data[26:28]))

							if id < startIcmpID || id > maxICMPid || maxSeq < seq {
								continue
							}

							hopS := (*hops[hosts[id-startIcmpID]])
							hopS[seq%maxttl][seq/maxttl].Addr = addr
							hopS[seq%maxttl][seq/maxttl].RTT = time.Since((*sendOn[hosts[id-startIcmpID]])[seq%maxttl][seq/maxttl])
							hopS[seq%maxttl][seq/maxttl].Timeout = false
						}
					}
				case ipv6.ICMPTypeEchoReply:
					if rply, ok := result.Body.(*icmp.Echo); ok {

						if rply.ID < startIcmpID || rply.ID > maxICMPid || maxSeq < rply.Seq {
							continue
						}

						hopS := (*hops[hosts[rply.ID-startIcmpID]])
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Addr = addr
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].RTT = time.Since((*sendOn[hosts[rply.ID-startIcmpID]])[rply.Seq%maxttl][rply.Seq/maxttl])
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Final = true
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Timeout = false
					}
				case ipv6.ICMPTypeDestinationUnreachable:
					if rply, ok := result.Body.(*icmp.Echo); ok {

						if rply.ID < startIcmpID || rply.ID > maxICMPid || maxSeq < rply.Seq {
							continue
						}

						hopS := (*hops[hosts[rply.ID-startIcmpID]])
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Addr = addr
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].RTT = time.Since((*sendOn[hosts[rply.ID-startIcmpID]])[rply.Seq%maxttl][rply.Seq/maxttl])
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Down = true
						hopS[rply.Seq%maxttl][rply.Seq/maxttl].Timeout = false
					}
				}
			}

		}()
	}

	wg.Wait()

	for _, host := range hosts {
		finalHop := maxttl
		hopS := (*hops[host])

		for hop := 0; hop < maxttl; hop++ {
			for r := 0; r < rounds; r++ {
				if nil == hopS[hop][r].Addr {
					continue
				}
				if nil != DNScache {
					addrString := hopS[hop][r].Addr.String()
					hopS[hop][r].Host = DNScache.LookupHost(addrString)
					hopS[hop][r].AS = DNScache.LookupAS(addrString)
				}
				if maxttl == finalHop && hopS[hop][r].Final {
					finalHop = hop + 1
				}
			}
		}
		hopS = hopS[:finalHop]
		hops[host] = &(hopS)
	}

	return hops, nil
}
