# tracelib
Traceroute implementation in go including mutli-round trace (returns min/max/avg/lost) and AS number detection both for IPv4 and IPv6. Also expremental implementation of much faster traceroute present (it sends all packets with all possible TTLs at once and total tracroute time is always the same as MaxRTT), look at examples/parallel for more info.

Usage example of regular traceroute (only IPs without hostnames and AS numbers):
```go
hops, err := tracelib.RunTrace("google.com", "0.0.0.0", time.Second, 64, nil)
for i, hop := range hops {
	fmt.Printf("%d. %v(%s)/AS%d %v (final:%v timeout:%v error:%v)\n",
      i+1, hop.Host, hop.Addr, hop.AS, hop.RTT, hop.Final, hop.Timeout, hop.Error)
}
```

Multiply traces with hostnames and AS numbers:
```go
dnscache := tracelib.NewLookupCache()
rawHops, err := tracelib.RunMultiTrace("homebeat.live", "0.0.0.0", time.Second, 64, dnscache, 5)

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
