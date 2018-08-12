# SAWL
## Introduction
**S**ubscriber **A**ware **W**eb **L**ogger is libpcap based process that create web usage logs (based on HTTP, DNS and SNI) correlated with subscriber information (based on RADIUS).
Execution requires root priviliages to sniff traffic off the interface. Subscriber data is kep in memory, but also stored in REDIS to allow for fater ramp-up after restarts, for that REDIS needs to be installed.

## Usage
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
Alternatively, following script: `run_sawl.sh` may be used, where configuration will be coming from a file: `sawl.conf`. If the script is used, the log will be written to `/var/log/sawl.log` and not to screen.

## Building
In order to build, use `make`, however, software has dependencies with following libraries:
* libpcap (for reading packets from the interface). On Redhat/Centos/Fedora etc. systems use: `sudo yum install libpcap-devel`
* libssl and libcrypto (for SNI). On Redhat/Centos/Fedora etc. systems use: `sudo yum install openssl-devel`
* [libhiredis](https://github.com/redis/hiredis) (C interface to REDIS). The `fetch_dependencies.sh` script could be used for that, and calling `make` should build hiredis

## Docker
To create a [docker](https://www.docker.com/community-edition) image, use: `make docker`. To run a container based on this image, use: 
`sudo docker run --rm --net=host -d --name sawl-daemon -v /var/log:/var/log -v <output dir>:/home/sawl/bin/output -v <conf dir>:/home/sawl/conf sawld`
Where `<output dir>` is a directory on the host where the output files will be generated. And `<conf dir>` is where the conf file for this container should be stored. This will run the container in the background and delete it after it finishes.
### Redis
For quick ramp up, subscriber mapping to IP addresses may be persisted into [redis](https://redis.io/). When running in a dockerized environment, this could be achieved by running a redis docker image: `sudo docker run --rm --net=host --name sawl-redis -d -v <host dir>:/data redis`. Where `<host dir>` is a directory on the host where the redis dump file will be persisted.
### Orchestration
In some cases, the host would have multiple network interfaces. In this case multiple docker containers should run, each one with their oun configuration (number of workers in each container is also dependend with available hardware).
