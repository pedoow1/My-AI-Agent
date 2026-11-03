#!/usr/bin/env bash
# CyberSentinel Background Mission Runner
# Runs a CyberSentinel scan inside a detached tmux session with persistent logging.

TARGET="${1:-.}"
REPORT_DIR="reports"
LOG_FILE="$REPORT_DIR/mission_output.log"
SESSION_NAME="cybersentinel-mission"

mkdir -p "$REPORT_DIR"

# Check if tmux is installed
if ! command -v tmux &> /dev/null; then
    echo "tmux not found. Installing tmux..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y tmux
    elif command -v yum &> /dev/null; then
        sudo yum install -y tmux
    else
        echo "Error: tmux could not be automatically installed. Please install tmux manually."
        exit 1
    fi
fi

# Kill existing session if running
tmux has-session -t "$SESSION_NAME" 2>/dev/null && tmux kill-session -t "$SESSION_NAME"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/scan_report_$TIMESTAMP.md"

echo "Starting CyberSentinel background mission on target: $TARGET"
echo "Logs will be written to: $LOG_FILE"
echo "Report will be saved to: $REPORT_FILE"

# Start detached tmux session running the scan and teeing output to log file
tmux new-session -d -s "$SESSION_NAME" "python3 -m cybersentinel.cli scan \"$TARGET\" --output \"$REPORT_FILE\" --format md 2>&1 | tee \"$LOG_FILE\""

echo "Mission started in tmux session '$SESSION_NAME'."
echo "To reattach to the session, run: tmux attach -t $SESSION_NAME"
echo "To view live logs, run: tail -f $LOG_FILE"
echo "To check status, run: cybersentinel mission status"
