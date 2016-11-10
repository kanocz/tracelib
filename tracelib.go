package tracelib

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	// ProtocolICMP icmp protocol id
	ProtocolICMP = 1
)

// trace struct represents handles connections and info for trace
type trace struct {
	conn     net.PacketConn
	ipv4conn *ipv4.PacketConn
	msg      icmp.Message
	netmsg   []byte
	id       int
	maxrtt   time.Duration
	maxttl   int
	dest     net.Addr
}

// RunTrace preforms traceroute to specified host
func RunTrace(host string, source string, maxrtt time.Duration, maxttl int) ([]Hop, error) {
	hops := make([]Hop, 0, maxttl)

	var res trace
	var err error

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
		return nil, errors.New("Unable to resolve destination host")
	}

	res.maxrtt = maxrtt
	res.maxttl = maxttl
	res.id = rand.Int() % 0x7fff
	res.msg = icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: res.id, Seq: 1}}
	res.netmsg, err = res.msg.Marshal(nil)

	if nil != err {
		return nil, err
	}

	res.conn, err = net.ListenPacket("ip4:icmp", source)
	if nil != err {
		return nil, err
	}
	defer res.conn.Close()

	res.ipv4conn = ipv4.NewPacketConn(res.conn)
	defer res.ipv4conn.Close()

	for i := 1; i <= maxttl; i++ {
		next := res.Step(i)
		if nil != next.Addr {
			addrs, _ := net.LookupAddr(next.Addr.String())
			if len(addrs) > 0 {
				next.Host = addrs[0]
			}
		}
		hops = append(hops, next)
		if next.Final {
			break
		}
	}

	return hops, nil
}

// RunMultiTrace preforms traceroute to specified host testing each hop several times
func RunMultiTrace(host string, source string, maxrtt time.Duration, maxttl int, rounds int) ([][]Hop, error) {
	hops := make([][]Hop, 0, maxttl)

	var res trace
	var err error

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
		return nil, errors.New("Unable to resolve destination host")
	}

	res.maxrtt = maxrtt
	res.maxttl = maxttl
	res.id = rand.Int() % 0x7fff
	res.msg = icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: res.id, Seq: 1}}
	res.netmsg, err = res.msg.Marshal(nil)

	if nil != err {
		return nil, err
	}

	res.conn, err = net.ListenPacket("ip4:icmp", source)
	if nil != err {
		return nil, err
	}
	defer res.conn.Close()

	res.ipv4conn = ipv4.NewPacketConn(res.conn)
	defer res.ipv4conn.Close()

	hostnameCache := map[string]string{}

	for i := 1; i <= maxttl; i++ {
		thisHops := make([]Hop, 0, rounds)
		isFinal := false

		for j := 0; j < rounds; j++ {
			next := res.Step(i)
			if nil != next.Addr {
				addrString := next.Addr.String()
				if _, ok := hostnameCache[addrString]; !ok {
					addrs, _ := net.LookupAddr(addrString)
					if len(addrs) > 0 {
						hostnameCache[addrString] = addrs[0]
					} else {
						hostnameCache[addrString] = ""
					}
				}

				next.Host = hostnameCache[addrString]
			}
			thisHops = append(thisHops, next)
			isFinal = next.Final || isFinal
		}
		hops = append(hops, thisHops)
		if isFinal {
			break
		}
	}

	return hops, nil
}

// Hop represents each hop of trace
type Hop struct {
	Addr    net.Addr
	Host    string
	RTT     time.Duration
	Final   bool
	Timeout bool
	Error   error
}

// Step sends one echo packet and waits for result
func (t *trace) Step(ttl int) Hop {
	var hop Hop

	hop.Error = t.conn.SetReadDeadline(time.Now().Add(t.maxrtt))

	if nil != hop.Error {
		return hop
	}

	hop.Error = t.ipv4conn.SetTTL(ttl)
	if nil != hop.Error {
		return hop
	}

	sendOn := time.Now()

	_, hop.Error = t.conn.WriteTo(t.netmsg, t.dest)
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
		result, hop.Error = icmp.ParseMessage(ProtocolICMP, buf[:readLen])
		if nil != hop.Error {
			return hop
		}

		hop.RTT = time.Since(sendOn)

		if result.Type == ipv4.ICMPTypeEchoReply {
			if rply, ok := result.Body.(*icmp.Echo); ok {
				if t.id != rply.ID {
					continue
				}
				hop.Final = true
				return hop
			}
		}

		if result.Type == ipv4.ICMPTypeTimeExceeded {
			if rply, ok := result.Body.(*icmp.TimeExceeded); ok {
				if uint16(t.id) != binary.BigEndian.Uint16(rply.Data[24:26]) {
					continue
				}
				return hop
			}
		}

		// do we need check other types?..
	}
}
