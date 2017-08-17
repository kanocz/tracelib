package main

import (
	"fmt"
	"time"

	"github.com/kanocz/tracelib"
)

func main() {
	cache := tracelib.NewLookupCache()

	hops, err := tracelib.RunTrace("google.com", "0.0.0.0", time.Second, 64, cache, nil)

	if nil != err {
		fmt.Println("Traceroute error:", err)
		return
	}

	for i, hop := range hops {
		fmt.Printf("%d. %v(%s)/AS%d %v (final:%v timeout:%v error:%v)\n", i+1, hop.Host, hop.Addr, hop.AS, hop.RTT, hop.Final, hop.Timeout, hop.Error)
	}
}
