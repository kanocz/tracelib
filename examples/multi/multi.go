package main

import (
	"fmt"
	"time"

	"strings"

	"github.com/kanocz/tracelib"
)

func main() {
	rawHops, err := tracelib.RunMultiTrace("homebeat.live", "0.0.0.0", time.Second, 64, true, 5)

	if nil != err {
		fmt.Println("Traceroute error:", err)
		return
	}

	hops := tracelib.AggregateMulti(rawHops)

	for i, hop := range hops {
		isd := fmt.Sprintf("%d. ", i+1)
		isp := strings.Repeat(" ", len(isd))

		for j, h := range hop {
			prefix := isd
			if j > 0 {
				prefix = isp
			}

			fmt.Printf("%s%v(%s)/AS%d %v/%v/%v (final:%v lost %d of %d)\n", prefix, h.Host, h.Addr, h.AS, h.MinRTT, h.AvgRTT, h.MaxRTT, h.Final, h.Lost, h.Total)

		}
	}
}