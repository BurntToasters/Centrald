# User guide

Everyday tasks in the CentralD web app. If you have not installed it yet, start
with [Get started](QUICKSTART.md).

## Reading the Devices page

The tiles at the top count devices that are online now and that need attention.
A device needs attention when it has pending updates, needs a reboot, has failed
services, or has a disk at least 90% full.

Each row shows live CPU, memory, and fullest disk. Devices report every 15
seconds; a device counts as offline 90 seconds after it last reported. Use the
filter box to search by name, operating system, or address.

Select a device for:

- **Resources**: CPU, memory, swap, and every real disk.
- **Health**: pending updates, whether a reboot is needed, and failed systemd
  services. Updates are checked every six hours, or when you select **Check for
  updates**.
- **Last 24 hours**: a chart of CPU and memory.
- **System**: hostname, OS, kernel, architecture, uptime, addresses, agent
  version, and where it connects from.
- **Recent commands** run on this device.

To rename a device, select **Rename** in the System card. The name is only used
in CentralD.

## Running commands

Select **Run command**, pick one or more devices, type a command, and select
**Run on N devices**. You can also tick devices on the Devices page and select
**Run command on N selected**.

- On Linux the command runs with `/bin/sh -c` as root. On Windows it runs in
  PowerShell as SYSTEM.
- Output streams into the page as it arrives. Each device's output is kept up to
  1 MiB; anything beyond that is cut off and marked.
- Pick a time limit from 1 minute to 6 hours (default 5 minutes). When it runs
  out, CentralD stops the command and everything it started: it asks politely
  first, then forces it 10 seconds later.
- **Cancel** stops a running command the same way.
- Commands cannot ask questions. Use non-interactive flags, such as
  `apt-get -y`. For anything interactive, use the terminal.

The result for each device is one of:

| Result      | Meaning                                                      |
| ----------- | ------------------------------------------------------------ |
| Succeeded   | Exit code 0.                                                 |
| Failed      | Any other exit code, or the command could not start.         |
| Timed out   | Hit the time limit and was stopped.                          |
| Canceled    | Stopped by an operator.                                      |
| Refused     | The device is monitor-only, or already running 8 commands.   |
| Offline     | The device was offline when you ran it.                      |
| Interrupted | The device disconnected or the server restarted mid-command. |

**History** lists every run. Open one to see the output again, or select **Run
again** to reuse the command.

## Updates and reboots

On a device page:

- **Check for updates** refreshes the package lists and counts what is pending.
- **Install updates** installs everything pending:
  - Debian, Ubuntu, Raspberry Pi OS: `apt-get update` then `apt-get upgrade`,
    keeping your existing configuration files.
  - Fedora: `dnf upgrade`.
  - Arch: `pacman -Syu`.
- **Reboot** restarts the machine five seconds after you confirm.

On Windows, use Windows Update for updates for now; **Reboot** works.

To update many machines at once, run `apt-get update && apt-get -y upgrade` (or
your distribution's equivalent) on all of them from **Run command**.

## Terminal

**Open terminal** on a device page starts a real interactive shell (bash on
Linux, PowerShell on Windows) as root. Everything a normal terminal does works:
`htop`, `vim`, `tmux`, colors, and resizing.

- The terminal closes after 30 minutes without input, when your session ends
  (sign-out, a password change elsewhere, a password reset, or your operator
  account is removed), or when the device is removed.
- What you type and see is not recorded. **Activity** records that a terminal
  was opened and for how long.
- If the connection drops, select **Reconnect**. Each connection is a new shell;
  use `tmux` or `screen` if you want work to survive.

## Monitor-only devices

Some machines should never accept remote commands, such as a router VM or a
machine that holds backups. Enroll those as **Monitor only** when you create the
join code (or with `sudo centrald-agent enroll --monitor-only`).

The machine itself enforces this: its agent refuses every command, update,
reboot, and terminal, even if the server were compromised. The web app greys
those buttons out.

To change a device between modes, enroll it again on that machine:

```sh
sudo centrald-agent leave
sudo centrald-agent enroll --monitor-only   # or without the flag
```

and remove the old entry from the Devices page.

## Operators and sign-in

Everyone who signs in to CentralD is an operator with full access to every
device. Add operators under **Settings > Operators**; each sets their own
password and two-factor sign-in.

- **Two-factor sign-in**: **Settings > Set up two-factor sign-in**. Scan the QR
  code with an authenticator app (Aegis, 2FAS, Google Authenticator, 1Password,
  and others) and enter the code it shows.
- **Changing your password** signs you out everywhere else.
- After five wrong passwords, sign-in pauses for 30 seconds, then for longer
  each time.
- **Forgot your password?** On the server, run
  `sudo centrald-server reset-password <username>`. This also turns off that
  account's two-factor sign-in.

Sessions last up to 30 days and end after 7 days without use.

## Removing a device

On the device page, select **Remove device**. Its credential stops working at
once, the agent disconnects, open terminals close, and commands still running on
it are stopped and shown as interrupted; history is kept. To uninstall the agent
from the machine as well:

- Package install: `sudo apt purge centrald-agent` (or `dnf remove`,
  `pacman -R`).
- One-line install: `sudo centrald-agent leave`, then
  `sudo rm /usr/local/bin/centrald-agent`.
- Windows: in an Administrator PowerShell, run
  `& "$env:ProgramFiles\CentralD\centrald-agent.exe" leave`, then delete the
  `CentralD` folder in Program Files.

## On the managed machine

The agent has a few commands of its own:

```sh
sudo centrald-agent status    # enrolled? connected? which server?
sudo centrald-agent enroll    # join a server (asks for the join code)
sudo centrald-agent leave     # disconnect and remove the service
sudo centrald-agent update    # install the agent version your server offers
```

`enroll --server 192.168.1.10:7443` tries that address first, which helps when
the server's address changed after the join code was made. The machine still
checks the server's identity from the join code.

On Windows, the agent lives in `C:\Program Files\CentralD`. Quote the path
because of the space:

```powershell
& "C:\Program Files\CentralD\centrald-agent.exe" status
```
