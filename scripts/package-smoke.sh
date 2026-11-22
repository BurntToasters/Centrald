#!/usr/bin/env bash
# Package smoke test for a disposable Debian/Ubuntu host with systemd (CI).
# Installs the built .deb files and walks the novice path end to end:
#   server package -> setup -> install one-liner (download path, sudo)
#   -> command runs -> agent package takes over -> server restarts
#   -> reinstall repairs /etc/centrald -> remove/reinstall -> re-enroll
#   -> purge.
# Run as a non-root user with passwordless sudo, from the repository root.
#
# Failure modes covered:
# - Enrolling the server host locks user centrald out of /etc/centrald, so
#   the server dies at its next restart.
# - A broken /etc/centrald mode survives a package reinstall or upgrade.
# - The agent package leaves the install command's binary and unit behind,
#   or a later purge deletes the credential that agent still uses.
# - Remove then reinstall leaves the server enabled but stopped.
# - An upgrade re-enables a server the admin disabled.
set -euo pipefail

arch=$(dpkg --print-architecture)
server_deb=$(ls dist/centrald-server_*_"$arch".deb)
agent_deb=$(ls dist/centrald-agent_*_"$arch".deb)
base=https://127.0.0.1:7443
jar=$(mktemp)
trap 'rm -f "$jar"' EXIT

step() { printf '\n== %s\n' "$*"; }
api() { curl -fsSk -b "$jar" -c "$jar" -H "Origin: $base" -H 'content-type: application/json' "$@"; }
wait_for() {
	local what=$1 i
	shift
	for i in $(seq 1 60); do
		if "$@"; then return 0; fi
		sleep 1
	done
	echo "timed out waiting for $what" >&2
	sudo journalctl -u centrald-server -u centrald-agent --no-pager | tail -50 >&2
	return 1
}
online_count() { api "$base/api/devices" | jq '[.[] | select(.online)] | length'; }

step "install the server package"
sudo apt-get install -y "./$server_deb"
systemctl is-active centrald-server
sudo systemctl show centrald-server -p User | grep -qx 'User=centrald'
code=$(sudo centrald-server status | sed -n 's/^Setup code: //p')
test -n "$code"

step "first-run setup through the API"
api -d "$(jq -n --arg c "$code" '{setupCode: $c, username: "admin", password: "correct horse battery"}')" \
	"$base/api/setup" >/dev/null
test "$(sudo centrald-server status | grep -c '^Setup code: [A-Z0-9]')" = 0

step "the web app's Linux install command enrolls this machine"
command=$(api -d '{"name": "smoke", "serverAddress": "127.0.0.1:7443"}' "$base/api/join-tokens" | jq -r .linuxCommand)
sh -c "$command"
test -x /usr/local/bin/centrald-agent
systemctl is-active centrald-agent
wait_for "device online" test "$(online_count)" = 1

step "a command runs as root on the device"
device=$(api "$base/api/devices" | jq -r '.[0].id')
run=$(api -d "$(jq -n --arg d "$device" '{deviceIds: [$d], command: "id -u"}')" "$base/api/runs" | jq -r .id)
run_state() { api "$base/api/runs/$run" | jq -r '.targets[0].state'; }
wait_for "command result" test "$(run_state)" = succeeded
api "$base/api/runs/$run" | jq -r '.targets[0].output' | base64 -d | grep -qx 0

server_up() { curl -fsk -o /dev/null "$base/"; }
config_dir_mode() { stat -c %a /etc/centrald; }

step "the server survives a restart after enrolling its own host"
test "$(config_dir_mode)" = 755
sudo systemctl restart centrald-server
wait_for "server after restart" server_up
wait_for "device back online" test "$(online_count)" = 1

step "the agent package takes over the install command's agent"
sudo apt-get install -y "./$agent_deb"
test ! -e /usr/local/bin/centrald-agent
test ! -e /etc/systemd/system/centrald-agent.service
systemctl show centrald-agent -p ExecStart | grep -q /usr/bin/centrald-agent
systemctl is-active centrald-agent
wait_for "same device online via the package" test "$(online_count)" = 1

step "reinstalling the server repairs a locked /etc/centrald"
sudo chmod 0700 /etc/centrald
sudo apt-get install -y --reinstall "./$server_deb"
test "$(config_dir_mode)" = 755
wait_for "server after reinstall" server_up

step "remove then reinstall starts the server again"
sudo apt-get remove -y centrald-server
if systemctl is-active --quiet centrald-server; then exit 1; fi
sudo apt-get install -y "./$server_deb"
wait_for "server after reinstall" server_up

step "an upgrade keeps a disabled server disabled"
sudo systemctl disable --now centrald-server
sudo apt-get install -y --reinstall "./$server_deb"
if systemctl is-enabled --quiet centrald-server; then exit 1; fi
if systemctl is-active --quiet centrald-server; then exit 1; fi
sudo systemctl enable --now centrald-server
wait_for "server enabled again" server_up

step "the packaged agent leaves and enrolls again"
sudo centrald-agent leave
join=$(api -d '{"name": "smoke-pkg", "serverAddress": "127.0.0.1:7443"}' "$base/api/join-tokens" | jq -r .code)
printf '%s\n' "$join" | sudo centrald-agent enroll --key-stdin
systemctl is-active centrald-agent
test ! -e /etc/systemd/system/centrald-agent.service
wait_for "packaged device online" test "$(online_count)" = 1

step "purge removes services, credentials, and data"
sudo apt-get purge -y centrald-agent centrald-server
if systemctl is-active --quiet centrald-server; then exit 1; fi
if systemctl is-active --quiet centrald-agent; then exit 1; fi
test ! -e /etc/centrald/agent.toml
test ! -e /var/lib/centrald
test ! -e /etc/systemd/system/multi-user.target.wants/centrald-server.service
test ! -e /etc/systemd/system/multi-user.target.wants/centrald-agent.service

echo
echo "package smoke test passed"
