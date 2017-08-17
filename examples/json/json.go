package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/kanocz/tracelib"
)

type mtrhHost struct {
	IP   string `json:"ip"`
	Host string `json:"host"`
	AS   int64  `json:"as"`
	Min  string `json:"min"`
	Avg  string `json:"avg"`
	Max  string `json:"max"`
	Rcvd int    `json:"received"`
}

func doTrace(host string) ([]byte, error) {
	cache := tracelib.NewLookupCache()

	rawHops, err := tracelib.RunMultiTrace(host, "0.0.0.0", time.Second, 64, cache, 10, nil)
	if nil != err {
		return nil, err
	}
	hops := tracelib.AggregateMulti(rawHops)

	result := make([][]mtrhHost, 0, len(hops))

	for _, hop := range hops {
		nextSlice := make([]mtrhHost, 0, len(hop))

		for _, h := range hop {
			if nil == h.Addr {
				continue
			}
			next := mtrhHost{}
			next.AS = h.AS
			next.IP = h.Addr.String()
			next.Host = h.Host
			next.Avg = fmt.Sprintf("%.2f", float64(h.AvgRTT)/float64(time.Millisecond))
			next.Max = fmt.Sprintf("%.2f", float64(h.MaxRTT)/float64(time.Millisecond))
			next.Min = fmt.Sprintf("%.2f", float64(h.MinRTT)/float64(time.Millisecond))
			if h.Total == 0 {
				next.Rcvd = 0
			} else {
				next.Rcvd = (100 * h.Total) / 10
			}
			nextSlice = append(nextSlice, next)
		}

		result = append(result, nextSlice)
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if nil != err {
		return nil, err
	}

	return out, nil
}

func main() {

	j, err := doTrace("homebeat.live")

	if nil != err {
		log.Fatalln("Error: ", err)
	}

	fmt.Println(string(j))
}
