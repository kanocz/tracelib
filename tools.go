package tracelib

import (
	"fmt"
	"net"
	"strconv"
	"strings"
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
	Final  bool
}

// AggregateMulti process result of RunMultiTrace and create aggregated result
func AggregateMulti(hops [][]Hop) [][]MHop {

	result := make([][]MHop, 0, len(hops))

	for _, hop := range hops {
		thishop := map[string]MHop{}

		timesum := map[string]time.Duration{}

		for _, h := range hop {
			addrstring := h.Addr.String()

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
			if h.Timeout || nil != h.Error {
				mhop.Lost++
			} else {
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

// LookupAS returns AS number for IP using origin.asn.cymru.com service
func LookupAS(ip string) int64 {
	ipParts := strings.Split(ip, ".")
	if len(ipParts) != 4 {
		return -1
	}

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

	return asnum
}
