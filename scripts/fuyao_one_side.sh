#!/bin/bash

if [ $# -ne 4 ]; then
        echo "This script is to FULLY automate online boutique experiment."
        echo "Running this script on your local machine."
        echo "Make sure you have ssh access configured."
        echo "usage: $0 <url> <time (seconds)> <clients> <spawn_rate>"
    exit 1
fi

# locust config
url=$1
time=$2
clients=$3
spawn_rate=$4

WORKER_1=songyu@amd266.utah.cloudlab.us
WORKER_2=songyu@amd269.utah.cloudlab.us
LOAD_GEN=songyu@amd275.utah.cloudlab.us

# dir config
BASE_DIR=/users/songyu/palladium-gateway
LOAD_GEN_DIR=/users/songyu/spright/sigcomm-experiment/expt-1-online-boutique/load-generator
SET_FD_DIR=$BASE_DIR/sigcomm-experiment/expt-1-online-boutique


echo "setup worker 1"
ssh -q $WORKER_1 "tmux kill-session -t spright" # kill tmux session
ssh -q $WORKER_1 "tmux new-session -d -s spright -n demo" # create tmux session
ssh -q $WORKER_1 "tmux set-option -t spright remain-on-exit on"

echo "splited tmux panel"
# Create tmux panes remotely
ssh -q $WORKER_1 'bash -s' << ENDSSH
    echo "Creating tmux panes on $WORKER_1..."
    for j in {1..14}
    do
        tmux split-window -v -t spright:demo
        tmux select-layout -t spright:demo tiled
    done
ENDSSH

echo "start spright"
ssh -q $WORKER_1 'bash -s' <<ENDSSH
    for j in {1..14}
    do
        tmux send-keys -t spright:demo.\$j "cd $BASE_DIR" Enter
        sleep 0.1
    done

    echo "Running gateway and functions on $WORKER_1..."
    tmux send-keys -t spright:demo.1 "sudo ./run.sh shm_mgr cfg/online-boutique-multi-nodes-one-side.cfg" Enter
    sleep 10
    tmux send-keys -t spright:demo.2 "sudo ./run.sh gateway" Enter
    sleep 10
    tmux send-keys -t spright:demo.3 "sudo ./run.sh frontendservice 1" Enter
    sleep 1
    tmux send-keys -t spright:demo.7 "sudo ./run.sh recommendationservice 5" Enter
    sleep 1
    tmux send-keys -t spright:demo.9 "sudo ./run.sh checkoutservice 7" Enter
ENDSSH

echo "finished worker1"
echo "set up worker2"

ssh -q $WORKER_2 "tmux kill-session -t spright" # kill tmux session
ssh -q $WORKER_2 "tmux new-session -d -s spright -n demo" # create tmux session
ssh -q $WORKER_2 "tmux set-option -t spright remain-on-exit on"

echo "splited tmux panel"
# Create tmux panes remotely
ssh -q $WORKER_2 'bash -s' << ENDSSH
    echo "Creating tmux panes on $WORKER_2..."
    for j in {1..14}
    do
        tmux split-window -v -t spright:demo
        tmux select-layout -t spright:demo tiled
    done
ENDSSH

echo "start spright"
ssh -q $WORKER_2 'bash -s' << ENDSSH
    for j in {1..14}
    do
        tmux send-keys -t spright:demo.\$j "cd $BASE_DIR" Enter
        sleep 0.1
    done

    echo "Running gateway and functions on $WORKER_2..."
    tmux send-keys -t spright:demo.1 "sudo ./run.sh shm_mgr cfg/online-boutique-multi-nodes-one-side.cfg" Enter
    sleep 10
    tmux send-keys -t spright:demo.2 "sudo ./run.sh gateway" Enter
    sleep 10
    tmux send-keys -t 4 "sudo ./run.sh currencyservice 2" Enter
    sleep 1
    tmux send-keys -t 5 "sudo ./run.sh productcatalogservice 3" Enter
    sleep 1
    tmux send-keys -t 6 "sudo ./run.sh cartservice 4" Enter
    sleep 1
    tmux send-keys -t 8 "sudo ./run.sh shippingservice 6" Enter
    sleep 1
    tmux send-keys -t 10 "sudo ./run.sh paymentservice 8" Enter
    sleep 1
    tmux send-keys -t 11 "sudo ./run.sh emailservice 9" Enter
    sleep 1
    tmux send-keys -t 12 "sudo ./run.sh adservice 10" Enter
ENDSSH

echo "finished worker2"
# exit

sleep 10

echo "setup loadgen"
ssh -q $LOAD_GEN "tmux kill-session -t spright" # kill tmux session
ssh -q $LOAD_GEN "tmux new-session -d -s spright -n demo" # create tmux session
ssh -q $LOAD_GEN "tmux set-option -t spright remain-on-exit on"

echo "splited tmux panel"
# Create tmux panes remotely
ssh -q $LOAD_GEN 'bash -s' << ENDSSH
   echo "Creating tmux panes on $LOAD_GEN..."
   for j in {1..19}
   do
       tmux split-window -v -t spright:demo
       tmux select-layout -t spright:demo tiled
       sleep 0.2
   done
ENDSSH

echo "start loadgen"
# Run LOAD_GEN
ssh -q $LOAD_GEN 'bash -s' << ENDSSH
    for j in {1..17}
    do
        tmux send-keys -t spright:demo.\$j "cd $LOAD_GEN_DIR" Enter
        sleep 0.1
    done

    echo "Running $clients clients on locust"
    tmux send-keys -t spright:demo.1 "yes | rm res*" Enter
    tmux send-keys -t spright:demo.1 "locust -u $clients -r $clients -t $time --csv res --csv-full-history -f spright-locustfile.py --headless -H $url --master --expect-workers=16" Enter
ENDSSH

sleep 0.1

echo "run load gen"
# Run LOAD_GEN
ssh -q $LOAD_GEN 'bash -s' << ENDSSH
    echo "Run locust workers in each tmux pane..."
    for j in {2..17}
    do
        tmux send-keys -t spright:demo.\$j "ulimit -HSn 102400 && locust -f spright-locustfile.py --worker" Enter
        sleep 1
    done
ENDSSH

echo "sleep for $((time+10)) before downloading results"
sleep $((time+10))

# Download results
DOWNLOAD_DIR=fuyao_result_$(date +%Y-%m-%d-%H-%M)
mkdir ./$DOWNLOAD_DIR
scp -q "$LOAD_GEN:$LOAD_GEN_DIR/res*" ./$DOWNLOAD_DIR
