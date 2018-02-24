package main

import (
	"fmt"
	"time"

	"github.com/kanocz/tracelib"
)

func printStep(hop tracelib.Hop, num int, round int) {
	fmt.Printf("%d.(%d) %v(%s)/AS%d %v (final:%v timeout:%v error:%v down:%v)\n", num, round, hop.Host, hop.Addr, hop.AS, hop.RTT, hop.Final, hop.Timeout, hop.Error, hop.Down)
}

func main() {
	cache := tracelib.NewLookupCache()

	fmt.Println("Single round trace")
	_, err := tracelib.RunTrace("google.com", "0.0.0.0", "::", time.Second, 64, cache, printStep)

	if nil != err {
		fmt.Println("Traceroute error:", err)
		return
	}

	fmt.Println("Multi round trace")
	_, err = tracelib.RunMultiTrace("google.com", "0.0.0.0", "::", time.Second, 64, cache, 3, printStep)

	if nil != err {
		fmt.Println("Traceroute error:", err)
		return
	}

}
