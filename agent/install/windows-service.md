# Running the agent as a Windows service

The agent is a normal Python program, so any "run on boot / keep alive" method
works. Two common options:

## Option A — Task Scheduler (no extra software)

1. Install Python 3 (check "Add python.exe to PATH").
2. In the `agent` folder: `py -m pip install -r requirements.txt`
3. Open **Task Scheduler** > **Create Task**:
   - General: *Run whether user is logged on or not*, *Run with highest privileges*.
   - Triggers: **At startup** (and optionally "At log on").
   - Actions: **Start a program**
     - Program: `py`
     - Arguments: `-m printqueue_agent --config config.json`
     - Start in: the full path to the `agent` folder.
   - Settings: *If the task fails, restart every 1 minute*.

## Option B — NSSM (runs as a true Windows service)

1. Download [NSSM](https://nssm.cc/).
2. From an admin prompt:
   ```
   nssm install PrintQueueAgent "C:\Path\To\python.exe" "-m printqueue_agent --config C:\Path\To\agent\config.json"
   nssm set PrintQueueAgent AppDirectory "C:\Path\To\agent"
   nssm start PrintQueueAgent
   ```

## Finding the COM port

Run `py -m printqueue_agent --list-ports` to list serial ports, or check
**Device Manager > Ports (COM & LPT)**. Set `"serial_port": "COM3"` (or leave
`"auto"` to use the first available port).

> While the agent owns the COM port, Cura cannot be *connected* to the printer
> at the same time (you can still use Cura to slice). The agent automatically
> steps aside if the port is busy.
