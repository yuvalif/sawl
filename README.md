# SAWL
**S**ubscriber **A**ware **W**eb **L**ogger is libpcap based process that create web usage logs (based on HTTP, DNS and SNI) correlated with subscriber information (based on RADIUS).
Execution requires root priviliages to sniff traffic off the interface. Subscriber data is kep in memory, but also stored in REDIS to allow for fater ramp-up after restarts, for that REDIS needs to be installed.

All configuration is coming from commandline:
`TODO`

In order to build, use `make`, however, software has dependencies with following libraries:
* libpcap (for reading packets from the interface)
* libssl and libcrypto (for SNI)
* libhiredis (C interface to REDIS)
