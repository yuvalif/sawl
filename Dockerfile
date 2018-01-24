# base on fedora
FROM fedora:latest

# working directory for the application
RUN mkdir -p /home/sawl
RUN mkdir -p /home/sawl/bin
RUN mkdir -p /home/sawl/conf

# copy the binary and run script
COPY src/sawl /home/sawl/bin
COPY run_sawl.sh /home/sawl/bin

# copy the hiredis libs
COPY hiredis/libhiredis.so /usr/lib/libhiredis.so.0.13
RUN ln -sf /usr/lib/libhiredis.so.0.13 /usr/lib/libhiredis.so
COPY hiredis/libhiredis.a /usr/lib/

# install missing libraries
RUN yum -y install openssl

# run the application
WORKDIR /home/sawl/bin
CMD LD_LIBRARY_PATH=/usr/lib ./run_sawl.sh /home/sawl/conf/sawl.conf

