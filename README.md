# tracelib
Traceroute implementation in go including mutli-round trace (returns min/max/avg/lost) and AS number detection.

Usage example:
```go
hops, err := tracelib.RunTrace("google.com", "0.0.0.0", time.Second, 64, true)
for i, hop := range hops {
	fmt.Printf("%d. %v(%s)/AS%d %v (final:%v timeout:%v error:%v)\n",
      i+1, hop.Host, hop.Addr, hop.AS, hop.RTT, hop.Final, hop.Timeout, hop.Error)
}
```

And with multiply traces:
```go
rawHops, err := tracelib.RunMultiTrace("homebeat.live", "0.0.0.0", time.Second, 64, true, 5)

hops := tracelib.AggregateMulti(rawHops)

for i, hop := range hops {
	isd := fmt.Sprintf("%d. ", i+1)
	isp := strings.Repeat(" ", len(isd))

	for j, h := range hop {
		prefix := isd
        if j > 0 { prefix = isp }

		fmt.Printf("%s%v(%s)/AS%d %v/%v/%v (final:%v lost %d of %d)\n",
          prefix, h.Host, h.Addr, h.AS, h.MinRTT, h.AvgRTT, h.MaxRTT, h.Final, h.Lost, h.Total)
	}
}
```