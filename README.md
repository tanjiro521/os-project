# proc_monitor

A lightweight, interactive process monitor for Linux. It reads process and
system statistics from `/proc` and presents a terminal view that refreshes
once per second.

## Features

- Lists running processes with PID, user, state, CPU usage, resident memory,
  virtual memory, and command name.
- Shows system uptime, load averages, memory, swap, task count, and CPU count.
- Sorts processes by CPU usage, memory usage, or PID.
- Adapts the display to the current terminal size and responds to resize events.

## Requirements

- Linux with `/proc` mounted.
- A C compiler such as GCC.
- A terminal for the interactive display.

## Build

From the project directory, run:

```sh
gcc -O2 -Wall -Wextra -o proc_monitor file.c
```

## Run

```sh
./proc_monitor
```

Press `q` to quit. The program also exits on `Ctrl+C`.

## Keyboard controls

| Key | Action |
| --- | --- |
| `c` | Sort by CPU usage |
| `m` | Sort by resident memory |
| `p` | Sort by process ID |
| `q` | Quit |

CPU usage is calculated from changes in process CPU time between refreshes, so
the first screen may show little or no CPU activity.
