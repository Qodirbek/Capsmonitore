#!/data/data/com.termux/files/usr/bin/bash
cd "$(dirname "$0")"
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock
[ -f config.json ] || cp config.example.json config.json
if command -v tmux >/dev/null 2>&1; then
  tmux has-session -t capsreport 2>/dev/null && tmux kill-session -t capsreport
  tmux new-session -d -s capsreport "python reporter.py"
  echo "reporter tmux: capsreport"
else
  nohup python reporter.py >/dev/null 2>&1 &
  echo "reporter PID $!"
fi
