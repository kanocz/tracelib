package tracelib

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MHop represents aggregated result of hop of multiply traces
type MHop struct {
	Addr   net.Addr
	Host   string
	AS     int64
	MinRTT time.Duration
	MaxRTT time.Duration
	AvgRTT time.Duration
	Total  int
	Lost   int
	Down   int
	Final  bool
}

// AggregateMulti process result of RunMultiTrace and create aggregated result
func AggregateMulti(hops [][]Hop) [][]MHop {

	result := make([][]MHop, 0, len(hops))

	for _, hop := range hops {
		thishop := map[string]MHop{}

		timesum := map[string]time.Duration{}

		for _, h := range hop {
			var addrstring string
			if nil != h.Addr {
				addrstring = h.Addr.String()
			}

			var (
				mhop MHop
				ok   bool
			)

			if mhop, ok = thishop[addrstring]; !ok {
				mhop.Addr = h.Addr
				mhop.Host = h.Host
				mhop.AS = h.AS
				mhop.Final = h.Final
				timesum[addrstring] = 0
			}

			mhop.Total++

			switch {
			case h.Down:
				mhop.Down++
			case h.Timeout || nil != h.Error:
				mhop.Lost++
			default:
				timesum[addrstring] += h.RTT
				if mhop.MaxRTT < h.RTT {
					mhop.MaxRTT = h.RTT
				}
				if mhop.MinRTT == 0 || mhop.MinRTT > h.RTT {
					mhop.MinRTT = h.RTT
				}
			}

			mhop.Final = mhop.Final || h.Final
			if mhop.Total > mhop.Lost {
				mhop.AvgRTT = timesum[addrstring] / time.Duration(mhop.Total-mhop.Lost)
			}
			thishop[addrstring] = mhop
		}

		thisSlice := make([]MHop, 0, len(thishop))
		for _, h := range thishop {
			thisSlice = append(thisSlice, h)
		}

		result = append(result, thisSlice)
	}

	return result

}

// LookupCache used to prevent AS-DNS requests for same hosts
type LookupCache struct {
	as     map[string]int64
	aMutex sync.RWMutex
	hosts  map[string]string
	hMutex sync.RWMutex
}

// NewLookupCache constructor for LookupCache
func NewLookupCache() *LookupCache {
	return &LookupCache{
		as:    make(map[string]int64, 1024),
		hosts: make(map[string]string, 4096),
	}
}

// LookupAS returns AS number for IP using origin.asn.cymru.com service
func (cache *LookupCache) LookupAS(ip string) int64 {
	cache.aMutex.RLock()
	v, exist := cache.as[ip]
	cache.aMutex.RUnlock()
	if exist {
		return v
	}

	ipParts := strings.Split(ip, ".")
	if len(ipParts) == 4 {
		return cache.lookupAS4(ip, ipParts)
	}

	return cache.lookupAS6(ip)
}

func (cache *LookupCache) lookupAS4(ip string, ipParts []string) int64 {

	txts, err := net.LookupTXT(fmt.Sprintf("%s.%s.%s.%s.origin.asn.cymru.com", ipParts[3], ipParts[2], ipParts[1], ipParts[0]))
	if nil != err || nil == txts || len(txts) < 1 {
		return -1
	}

	parts := strings.Split(txts[0], " | ")
	if len(parts) < 2 {
		return -1
	}

	asnum, err := strconv.ParseInt(parts[0], 10, 64)
	if nil != err {
		return -1
	}

	cache.aMutex.Lock()
	cache.as[ip] = asnum
	cache.aMutex.Unlock()

	return asnum
}

func (cache *LookupCache) lookupAS6(ip string) int64 {

	i6 := net.ParseIP(ip)
	if len(i6) != 16 {
		return -1
	}

	hexIP := ""
	for _, v := range hex.EncodeToString([]byte(i6)) {
		hexIP = string(v) + "." + hexIP
	}

	txts, err := net.LookupTXT(hexIP + "origin6.asn.cymru.com")
	if nil != err || nil == txts || len(txts) < 1 {
		return -1
	}

	parts := strings.Split(txts[0], " | ")
	if len(parts) < 2 {
		return -1
	}

	asnum, err := strconv.ParseInt(parts[0], 10, 64)
	if nil != err {
		return -1
	}

	cache.aMutex.Lock()
	cache.as[ip] = asnum
	cache.aMutex.Unlock()

	return asnum
}

// LookupHost returns AS number for IP using origin.asn.cymru.com service
func (cache *LookupCache) LookupHost(ip string) string {
	cache.hMutex.RLock()
	v, exist := cache.hosts[ip]
	cache.hMutex.RUnlock()
	if exist {
		return v
	}

	var result string

	addrs, _ := net.LookupAddr(ip)
	if len(addrs) > 0 {
		result = addrs[0]
	}

	cache.hMutex.Lock()
	cache.hosts[ip] = result
	cache.hMutex.Unlock()

	return result
}
