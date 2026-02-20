#!/bin/bash
# tmux setup for DNE with NADINO-ingress - worker1 host
# Creates 16 panels and pre-fills commands without executing them

SESSION="dne_host1"
WINDOW="host1"

# Kill existing session if it exists
tmux kill-session -t "$SESSION" 2>/dev/null

# Create new detached session
tmux new-session -d -s "$SESSION" -n "$WINDOW" -x 220 -y 60

# Create 15 more panes (total 16) with tiled layout
for i in $(seq 1 15); do
    tmux split-window -t "$SESSION:$WINDOW"
    tmux select-layout -t "$SESSION:$WINDOW" tiled
done

# Final tiled layout
tmux select-layout -t "$SESSION:$WINDOW" tiled

# Commands for host1 - DNE with NADINO-ingress (worker1 host)
# Pane 0: shm_mgr
tmux send-keys -t "$SESSION:$WINDOW.0" "sudo ./run.sh shm_mgr ./cfg/ae_online-boutique-palladium-dpu.cfg"

# Pane 1: sockmap_manager
tmux send-keys -t "$SESSION:$WINDOW.1" "sudo ./run.sh sockmap_manager"

# Pane 2: frontendservice
tmux send-keys -t "$SESSION:$WINDOW.2" "sudo ./run.sh frontendservice 1"

# Pane 3: recommendationservice
tmux send-keys -t "$SESSION:$WINDOW.3" "sudo ./run.sh recommendationservice 5"

# Pane 4: checkoutservice
tmux send-keys -t "$SESSION:$WINDOW.4" "sudo ./run.sh checkoutservice 7"

# Panes 5-15: spare panels

# Select pane 0 to start
tmux select-pane -t "$SESSION:$WINDOW.0"

# Attach to session
tmux attach-session -t "$SESSION"
