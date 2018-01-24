#!/bin/bash

# prase parameter file and convert to sawl command-line
if [ "$#" -ne 1 ]; then
    source sawl.conf
else
    source $1
fi

# run the program with relevant parameters
./sawl -i $interface -r $redis_host:$redis_port -p $csv_rotation_period -s $snap_len -u $url_lrn -l -w $number_of_workers > /var/log/sawl.log

