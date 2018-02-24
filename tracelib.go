package tracelib

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// ProtocolICMP icmp protocol id
	ProtocolICMP = 1
	// ProtocolICMP6 icmp protocol id
	ProtocolICMP6 = 58

	// MaxTimeouts sets number of hops without replay before trace termination
	MaxTimeouts = 3
)

// trace struct represents handles connections and info for trace
type trace struct {
	conn     net.PacketConn
	ipv4conn *ipv4.PacketConn
	ipv6conn *ipv6.PacketConn
	msg      icmp.Message
	netmsg   []byte
	id       int
	maxrtt   time.Duration
	maxttl   int
	dest     net.Addr
}

// Callback function called after every hop received
type Callback func(info Hop, hopnum int, round int)

// RunTrace preforms traceroute to specified host
func RunTrace(host string, source string, source6 string, maxrtt time.Duration, maxttl int, DNScache *LookupCache, cb Callback) ([]Hop, error) {
	hops := make([]Hop, 0, maxttl)

	var res trace
	var err error
	isIPv6 := false

	addrList, err := net.LookupIP(host)
	if nil != err {
		return nil, err
	}

	for _, addr := range addrList {
		if addr.To4() != nil {
			res.dest, err = net.ResolveIPAddr("ip4:icmp", addr.String())
			break
		}
	}

	if nil == res.dest {
		for _, addr := range addrList {
			if addr.To16() != nil {
				isIPv6 = true
				res.dest, err = net.ResolveIPAddr("ip6:58", addr.String())
				break
			}
		}
	}
	if nil == res.dest {
		return nil, errors.New("Unable to resolve destination host")
	}

	res.maxrtt = maxrtt
	res.maxttl = maxttl
	res.id = rand.Int() % 0x7fff
	if isIPv6 {
		res.msg = icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &icmp.Echo{ID: res.id, Seq: 1}}
	} else {
		res.msg = icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: res.id, Seq: 1}}
	}
	res.netmsg, err = res.msg.Marshal(nil)

	if nil != err {
		return nil, err
	}

	if !isIPv6 {
		res.conn, err = net.ListenPacket("ip4:icmp", source)
	} else {
		res.conn, err = net.ListenPacket("ip6:58", source6)
	}
	if nil != err {
		return nil, err
	}
	defer res.conn.Close()

	if isIPv6 {
		res.ipv6conn = ipv6.NewPacketConn(res.conn)
		defer res.ipv6conn.Close()
		if err := res.ipv6conn.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagSrc|ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
			return nil, err
		}
		var f ipv6.ICMPFilter
		f.SetAll(true)
		f.Accept(ipv6.ICMPTypeTimeExceeded)
		f.Accept(ipv6.ICMPTypeEchoReply)
		f.Accept(ipv6.ICMPTypeDestinationUnreachable)
		if err := res.ipv6conn.SetICMPFilter(&f); err != nil {
			return nil, err
		}
	} else {
		res.ipv4conn = ipv4.NewPacketConn(res.conn)
		defer res.ipv4conn.Close()
	}

	timeouts := 0
	for i := 1; i <= maxttl; i++ {
		next := res.Step(i)
		if nil != next.Addr {
			addrString := next.Addr.String()
			if nil != DNScache {
				next.Host = DNScache.LookupHost(addrString)
				next.AS = DNScache.LookupAS(addrString)
			}
		}
		if nil != cb {
			cb(next, i, 1)
		}
		hops = append(hops, next)
		if next.Final {
			break
		}
		if next.Timeout {
			timeouts++
		} else {
			timeouts = 0
		}
		if timeouts == MaxTimeouts {
			break
		}
	}

	return hops, nil
}

// RunMultiTrace preforms traceroute to specified host testing each hop several times
func RunMultiTrace(host string, source string, source6 string, maxrtt time.Duration, maxttl int, DNScache *LookupCache, rounds int, cb Callback) ([][]Hop, error) {
	hops := make([][]Hop, 0, maxttl)

	var res trace
	var err error
	isIPv6 := false

	addrList, err := net.LookupIP(host)
	if nil != err {
		return nil, err
	}

	for _, addr := range addrList {
		if addr.To4() != nil {
			res.dest, err = net.ResolveIPAddr("ip4:icmp", addr.String())
			break
		}
	}

	if nil == res.dest {
		for _, addr := range addrList {
			if addr.To16() != nil {
				isIPv6 = true
				res.dest, err = net.ResolveIPAddr("ip6:58", addr.String())
				break
			}
		}
	}
	if nil == res.dest {
		return nil, errors.New("Unable to resolve destination host")
	}

	res.maxrtt = maxrtt
	res.maxttl = maxttl
	res.id = rand.Int() % 0x7fff
	if isIPv6 {
		res.msg = icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &icmp.Echo{ID: res.id, Seq: 1}}
	} else {
		res.msg = icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: res.id, Seq: 1}}
	}
	res.netmsg, err = res.msg.Marshal(nil)

	if nil != err {
		return nil, err
	}

	if !isIPv6 {
		res.conn, err = net.ListenPacket("ip4:icmp", source)
	} else {
		res.conn, err = net.ListenPacket("ip6:58", source6)
	}
	if nil != err {
		return nil, err
	}
	defer res.conn.Close()

	if isIPv6 {
		res.ipv6conn = ipv6.NewPacketConn(res.conn)
		defer res.ipv6conn.Close()
		if err := res.ipv6conn.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagSrc|ipv6.FlagDst|ipv6.FlagInterface, true); err != nil {
			return nil, err
		}
		// var f ipv6.ICMPFilter
		// f.SetAll(true)
		// f.Accept(ipv6.ICMPTypeTimeExceeded)
		// f.Accept(ipv6.ICMPTypeEchoReply)
		// if err := res.ipv6conn.SetICMPFilter(&f); err != nil {
		// 	return nil, err
		// }
	} else {
		res.ipv4conn = ipv4.NewPacketConn(res.conn)
		defer res.ipv4conn.Close()
	}

	timeouts := 0
	for i := 1; i <= maxttl; i++ {
		thisHops := make([]Hop, 0, rounds)
		isFinal := false

		notimeout := true
		for j := 0; j < rounds; j++ {
			next := res.Step(i)
			if nil != next.Addr {
				addrString := next.Addr.String()
				if nil != DNScache {
					next.Host = DNScache.LookupHost(addrString)
					next.AS = DNScache.LookupAS(addrString)
				}
			}
			if nil != cb {
				cb(next, i, j+1)
			}
			thisHops = append(thisHops, next)
			isFinal = next.Final || isFinal
			notimeout = notimeout && (!next.Timeout)
		}
		hops = append(hops, thisHops)
		if isFinal {
			break
		}
		if notimeout {
			timeouts = 0
		} else {
			timeouts++
		}

		if timeouts == MaxTimeouts {
			break
		}
	}

	return hops, nil
}

// Hop represents each hop of trace
type Hop struct {
	Addr    net.Addr
	Host    string
	AS      int64
	RTT     time.Duration
	Final   bool
	Timeout bool
	Down    bool
	Error   error
}

// Step sends one echo packet and waits for result
func (t *trace) Step(ttl int) Hop {
	var hop Hop
	var wcm ipv6.ControlMessage

	hop.Error = t.conn.SetReadDeadline(time.Now().Add(t.maxrtt))

	if nil != hop.Error {
		return hop
	}

	if nil != t.ipv4conn {
		hop.Error = t.ipv4conn.SetTTL(ttl)
	}
	if nil != t.ipv6conn {
		wcm.HopLimit = ttl
	}
	if nil != hop.Error {
		return hop
	}

	sendOn := time.Now()

	if nil != t.ipv4conn {
		_, hop.Error = t.conn.WriteTo(t.netmsg, t.dest)
	}
	if nil != t.ipv6conn {
		_, hop.Error = t.ipv6conn.WriteTo(t.netmsg, &wcm, t.dest)
	}
	if nil != hop.Error {
		return hop
	}

	buf := make([]byte, 1500)

	for {
		var readLen int

		readLen, hop.Addr, hop.Error = t.conn.ReadFrom(buf)

		if nerr, ok := hop.Error.(net.Error); ok && nerr.Timeout() {
			hop.Timeout = true
			return hop
		}

		if nil != hop.Error {
			return hop
		}

		var result *icmp.Message
		if nil != t.ipv4conn {
			result, hop.Error = icmp.ParseMessage(ProtocolICMP, buf[:readLen])
		}
		if nil != t.ipv6conn {
			result, hop.Error = icmp.ParseMessage(ProtocolICMP6, buf[:readLen])
		}
		if nil != hop.Error {
			return hop
		}

		hop.RTT = time.Since(sendOn)

		switch result.Type {
		case ipv4.ICMPTypeEchoReply:
			if rply, ok := result.Body.(*icmp.Echo); ok {
				if t.id != rply.ID {
					continue
				}
				hop.Final = true
				return hop
			}
		case ipv4.ICMPTypeTimeExceeded:
			if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
				if len(rply.Data) > 24 {
					if uint16(t.id) != binary.BigEndian.Uint16(rply.Data[24:26]) {
						continue
					}
					return hop
				}
			}
		case ipv6.ICMPTypeTimeExceeded:
			if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
				if len(rply.Data) > 44 {
					if uint16(t.id) != binary.BigEndian.Uint16(rply.Data[44:46]) {
						continue
					}
					return hop
				}
			}
		case ipv6.ICMPTypeEchoReply:
			if rply, ok := result.Body.(*icmp.Echo); ok {
				if t.id != rply.ID {
					continue
				}
				hop.Final = true
				return hop
			}
		case ipv6.ICMPTypeDestinationUnreachable:
			if rply, ok := result.Body.(*icmp.Echo); ok {
				if t.id != rply.ID {
					continue
				}
				hop.Down = true
				return hop
			}
		case ipv4.ICMPTypeDestinationUnreachable:
			if rply, ok := result.Body.(*icmp.Echo); ok {
				if t.id != rply.ID {
					continue
				}
				hop.Down = true
				return hop
			}
		}
	}
}
