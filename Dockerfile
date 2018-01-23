# base on fedora
FROM fedora:latest

# working directory for the application
RUN mkdir -p /home/sawl

# copy the binary
COPY src/sawl /home/sawl/

# copy the hiredis libs
COPY hiredis/libhiredis.so /usr/lib/libhiredis.so.0.13
RUN ln -sf /usr/lib/libhiredis.so.0.13 /usr/lib/libhiredis.so
COPY hiredis/libhiredis.a /usr/lib/

# install some missing stuff - libraries and debug tools
RUN yum -y install libpcap
RUN yum -y install openssl

# run the application
CMD LD_LIBRARY_PATH=/usr/lib /home/sawl/sawl -i lo -w 2 -t 10 > /var/log/sawl.log

