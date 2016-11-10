package tracelib

import (
	"net"
	"time"
)

// MHop represents aggregated result of hop of multiply traces
type MHop struct {
	Addr   net.Addr
	Host   string
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
