#!/bin/bash
count=1
protocol=PSM2

if [ ! -d "./build" ];then
	cmake -B build
	cmake --build build -j8
fi

if [ $# -eq 2 ];then
	count=$1
	protocol=$2
elif [ $# -eq 1 ];then
	count=$1
fi


total_time_vrf=0.0
total_time_oprf1_client=0.0
total_time_oprf2_client=0.0
total_time_hint_comp_client=0.0
total_time_psm_client=0.0
total_time_oprf1_server=0.0
total_time_oprf2_server=0.0
total_time_hint_comp_server=0.0
total_time_psm_server=0.0
total_time_runtime_client=0.0
total_time_runtime_server=0.0

for ((i=0; i<count; i++))
do
    str=`date "+%Y-%m-%d %H:%M:%S"`
    echo $str  >> client.log & echo $str >> server.log
    ./build/bin/gcf_psi -r 0 -p 31000 -c 1 -s 4096 -n 20 -y $protocol >> server.log &
    echo "begin client"
    ./build/bin/gcf_psi -r 1 -a 127.0.0.1 -p 31000 -c 1 -s 4096 -n 20 -y $protocol >> client.log 
    wait


    last_client_log=$(tail -n 6 client.log)
    last_server_log=$(tail -n 6 server.log)
    


    total_time_oprf1_server=$(echo $total_time_oprf1_server + $(echo $last_server_log | grep -oP 'Time for OPRF1 \K[0-9\.]+') | bc)
    total_time_oprf2_server=$(echo $total_time_oprf2_server + $(echo $last_server_log | grep -oP 'Time for OPRF2 \K[0-9\.]+') | bc)
    total_time_hint_comp_server=$(echo $total_time_hint_comp_server + $(echo $last_server_log | grep -oP 'Time for hint computation \K[0-9\.]+') | bc)
    total_time_psm_server=$(echo $total_time_psm_server + $(echo $last_server_log | grep -oP 'Timing for PSM \K[0-9\.]+') | bc)
    total_time_runtime_server=$(echo $total_time_runtime_server + $(echo $last_server_log | grep -oP 'Total runtime w/o base OTs:\K[0-9\.]+') | bc)

    total_time_oprf1_client=$(echo $total_time_oprf1_client + $(echo $last_client_log | grep -oP 'Time for OPRF1 \K[0-9\.]+') | bc)
    total_time_oprf2_client=$(echo $total_time_oprf2_client + $(echo $last_client_log | grep -oP 'Time for OPRF2 \K[0-9\.]+') | bc)
    total_time_hint_comp_client=$(echo $total_time_hint_comp_client + $(echo $last_client_log | grep -oP 'Time for hint computation \K[0-9\.]+') | bc)
    total_time_psm_client=$(echo $total_time_psm_client + $(echo $last_client_log | grep -oP 'Timing for PSM \K[0-9\.]+') | bc)
    total_time_runtime_client=$(echo $total_time_runtime_client + $(echo $last_client_log | grep -oP 'Total runtime w/o base OTs:\K[0-9\.]+') | bc)

    sleep 2

done



average_oprf1_server=$(echo "$total_time_oprf1_server / $count" | bc -l)
average_oprf2_server=$(echo "$total_time_oprf2_server / $count" | bc -l)
average_hint_comp_server=$(echo "$total_time_hint_comp_server / $count" | bc -l)
average_psm_server=$(echo "$total_time_psm_server / $count" | bc -l)
average_runtime_server=$(echo "$total_time_runtime_server / $count" | bc -l)
average_oprf1_client=$(echo "$total_time_oprf1_client / $count" | bc -l)
average_oprf2_client=$(echo "$total_time_oprf2_client / $count" | bc -l)
average_hint_comp_client=$(echo "$total_time_hint_comp_client / $count" | bc -l)
average_psm_client=$(echo "$total_time_psm_client / $count" | bc -l)
average_runtime_client=$(echo "$total_time_runtime_client / $count" | bc -l)


echo "Average Server Times:"
echo "OPRF1: $average_oprf1_server ms"
echo "OPRF2: $average_oprf2_server ms"
echo "Hint Computation: $average_hint_comp_server ms"
echo "PSM: $average_psm_server ms"
echo "Total Runtime w/o Base OTs: $average_runtime_server ms"

echo "Average Client Times:"
echo "OPRF1: $average_oprf1_client ms"
echo "OPRF2: $average_oprf2_client ms"
echo "Hint Computation: $average_hint_comp_client ms"
echo "PSM: $average_psm_client ms"
echo "Total Runtime w/o Base OTs: $average_runtime_client ms"
