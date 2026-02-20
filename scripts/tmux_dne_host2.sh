#!/bin/bash
# tmux setup for DNE with NADINO-ingress - worker2 host
# Creates 16 panels and pre-fills commands without executing them

SESSION="dne_host2"
WINDOW="host2"

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

# Commands for host2 - DNE with NADINO-ingress (worker2 host)
# Pane 0: shm_mgr
tmux send-keys -t "$SESSION:$WINDOW.0" "sudo ./run.sh shm_mgr ./cfg/ae_online-boutique-palladium-dpu.cfg"

# Pane 1: sockmap_manager
tmux send-keys -t "$SESSION:$WINDOW.1" "sudo ./run.sh sockmap_manager"

# Pane 2: currencyservice
tmux send-keys -t "$SESSION:$WINDOW.2" "sudo ./run.sh currencyservice 2"

# Pane 3: productcatalogservice
tmux send-keys -t "$SESSION:$WINDOW.3" "sudo ./run.sh productcatalogservice 3"

# Pane 4: cartservice
tmux send-keys -t "$SESSION:$WINDOW.4" "sudo ./run.sh cartservice 4"

# Pane 5: shippingservice
tmux send-keys -t "$SESSION:$WINDOW.5" "sudo ./run.sh shippingservice 6"

# Pane 6: paymentservice
tmux send-keys -t "$SESSION:$WINDOW.6" "sudo ./run.sh paymentservice 8"

# Pane 7: emailservice
tmux send-keys -t "$SESSION:$WINDOW.7" "sudo ./run.sh emailservice 9"

# Pane 8: adservice
tmux send-keys -t "$SESSION:$WINDOW.8" "sudo ./run.sh adservice 10"

# Panes 9-15: spare panels

# Select pane 0 to start
tmux select-pane -t "$SESSION:$WINDOW.0"

# Attach to session
tmux attach-session -t "$SESSION"
