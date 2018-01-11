# SAWL
**S**ubscriber **A**ware **W**eb **L**ogger is libpcap based process that create web usage logs (based on HTTP, DNS and SNI) correlated with subscriber information (based on RADIUS).
Execution requires root priviliages to sniff traffic off the interface. Subscriber data is kep in memory, but also stored in REDIS to allow for fater ramp-up after restarts, for that REDIS needs to be installed.

All configuration is coming from commandline:
```
Usage: ./sawl [-i interface | -f tracefile]
          [-r redis_host[:port]]
          [-d debug_level (1-5)]
          [-p CSV rotation period (seconds)]
          [-s snap length (bytes)]
          [-t stats period (seconds)]
          [-e extended statistics]
          [-u URL length (bytes)]
          [-l for SLL/SNI]
          [-w workers threads number]
          [-b thread bucket size]
          [-o do not perform TCP/UDP processing]
          [-v print version and exit]
```

In order to build, use `make`, however, software has dependencies with following libraries:
* libpcap (for reading packets from the interface)
* libssl and libcrypto (for SNI)
* [libhiredis](https://github.com/redis/hiredis) (C interface to REDIS)
