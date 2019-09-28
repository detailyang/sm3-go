<p align="center">
  <b>
    <span style="font-size:larger;">sm3-go</span>
  </b>
  <br />
   <a href="https://travis-ci.org/detailyang/sm3-go"><img src="https://travis-ci.org/detailyang/sm3-go.svg?branch=master" /></a>
   <a href="https://ci.appveyor.com/project/detailyang/sm3-go"><img src="https://ci.appveyor.com/api/projects/status/mjxkry3bv16pl623?svg=true" /></a>
   <br />
   <b>sm3-go implements the SM3 hash algorithms as defined in the <a href="http://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf">中国国家密码管理局</a> which export the hash.Hash interface</b>
</p>

````bash
go test -benchmem -run="^$" github.com/detailyang/sm3-go/sm3 -bench Benchmark
goos: darwin
goarch: amd64
pkg: github.com/detailyang/sm3-go/sm3
BenchmarkHash8Bytes-8   	 1916566	       617 ns/op	  12.96 MB/s	       0 B/op	       0 allocs/op
BenchmarkHash1K-8       	  120079	      9759 ns/op	 104.92 MB/s	       0 B/op	       0 allocs/op
BenchmarkHash8K-8       	   15838	     72582 ns/op	 112.87 MB/s	       0 B/op	       0 allocs/op
PASS
ok  	github.com/detailyang/sm3-go/sm3	5.015s
````
