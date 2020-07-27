package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/kanocz/tracelib"
)

func main() {
	cache := tracelib.NewLookupCache()

	rawMHops, err := tracelib.RunMPTrace([]string{"homebeat.live", "cocopacket.com", "skorochod.cz"}, "0.0.0.0", "::", time.Second, 32, cache, 10, 100, time.Millisecond)

	if nil != err {
		fmt.Println("Traceroute error:", err)
		return
	}

	// fmt.Printf("%+v\n", rawHops)

	for host, rawHops := range rawMHops {

		fmt.Println("trace to ", host)

		hops := tracelib.AggregateMulti(*rawHops)

		for i, hop := range hops {
			isd := fmt.Sprintf("%d. ", i+1)
			isp := strings.Repeat(" ", len(isd))

			for j, h := range hop {
				prefix := isd
				if j > 0 {
					prefix = isp
				}

				if nil != h.Addr {
					fmt.Printf("%s%v(%s)/AS%d %v/%v/%v (final:%v lost %d of %d, down %d of %d)\n", prefix, h.Host, h.Addr, h.AS, h.MinRTT, h.AvgRTT, h.MaxRTT, h.Final, h.Lost, h.Total, h.Down, h.Total)
				} else {
					fmt.Printf("%s Lost: %d\n", prefix, h.Lost)
				}

			}
		}
	}
}
