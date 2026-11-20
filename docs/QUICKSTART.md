# Get started

CentralD lets you check on every machine in your home lab and run commands on
them from one web app. You install a small server once, then add each machine
with one command.

This takes about five minutes.

## What you need

- One always-on Linux machine for the server. A Raspberry Pi, a NAS VM, or a
  small container host is plenty. Debian, Ubuntu, Raspberry Pi OS, Fedora, and
  Arch have packages; any other x86_64 or ARM64 Linux can use the tarball.
- The machines you want to manage: Linux (x86_64 or ARM64) or Windows 10/11
  (x86_64 or ARM64).
- A private network between them: your LAN, or a VPN such as WireGuard or
  Tailscale. Do not expose CentralD to the Internet.

## 1. Install the server

Download the package for your server from the
[latest release](https://github.com/BurntToasters/centrald/releases), then:

**Debian, Ubuntu, Raspberry Pi OS**

```sh
sudo apt install ./centrald-server_*_amd64.deb   # or _arm64.deb
```

**Fedora**

```sh
sudo dnf install ./centrald-server-*.x86_64.rpm  # or .aarch64.rpm
```

**Arch**: download `PKGBUILD` and both `.install` files into one folder, then:

```sh
makepkg -si
sudo systemctl enable --now centrald-server
```

The server starts right away and prints something like this:

```text
Open the web app at:
  https://192.168.1.10:7443

Setup code: K7PX-2MQD-9RTA
Enter it in the web app to create the first account.
```

Run `sudo centrald-server status` any time to see this again.

If the server has a firewall, open port 7443 for TCP. The installer tells you
the exact command when UFW or firewalld is active, for example:

```sh
sudo ufw allow 7443/tcp
```

## 2. Create your account

1. Open the web address in a browser on any computer on your network.
2. Your browser warns that the connection is not private. That is expected:
   CentralD made its own certificate. Continue to the site. (To get rid of the
   warning, see [Trust the certificate](OPERATIONS.md#trust-the-certificate).)
3. Enter the setup code, pick a username and a password (at least 10
   characters), and select **Create account**.

Then turn on two-factor sign-in under **Settings**. This account can run
commands as root on your machines, so it deserves it.

## 3. Add a machine

1. Select **Add device**.
2. Check the server address. It must be an address the new machine can reach,
   such as `192.168.1.10:7443`. If you opened the web app on the server itself
   as `localhost`, change it to the server's LAN address.
3. Choose **Full control** or **Monitor only**:
   - **Full control**: health, commands, updates, reboots, and a terminal.
   - **Monitor only**: health only. The machine itself refuses every command, so
     a stolen CentralD account cannot touch it.
4. Select **Create join code**.
5. Copy the command for the machine and run it there:
   - **Linux**: paste it into a terminal. It asks for your sudo password.
   - **Windows**: open **Terminal (Admin)** and paste it.

The page shows **joined** a few seconds later. The command checks the server's
identity before downloading anything, installs the agent as a service, and uses
the join code once.

## 4. Use it

- **Devices** shows every machine with CPU, memory, disk, pending updates,
  reboot-needed, and failed services. Select one for details and a 24-hour
  chart.
- **Run command** runs a shell command on one or many machines and streams the
  output back. Commands run as root (Administrator on Windows).
- **Open terminal** on a device page gives you a full interactive shell in the
  browser.
- **Check for updates**, **Install updates**, and **Reboot** are one click on a
  device page.
- **History** keeps every command with its output; **Activity** records who did
  what.

## Next steps

- [User guide](GUIDE.md): everyday tasks, more operators, monitor-only machines.
- [Operations](OPERATIONS.md): configuration, your own certificate, backups,
  upgrades, and troubleshooting.
- [Security model](THREAT_MODEL.md): what CentralD protects and what it cannot.
