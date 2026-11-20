#!/usr/bin/env bash
# Package smoke test for a disposable Debian/Ubuntu host with systemd (CI).
# Installs the built .deb files and walks the novice path end to end:
#   server package -> setup -> install one-liner (download path, sudo)
#   -> command runs -> agent leaves -> agent package -> enroll -> purge.
# Run as a non-root user with passwordless sudo, from the repository root.
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

step "the agent leaves and the package-managed agent enrolls"
sudo centrald-agent leave
sudo rm -f /usr/local/bin/centrald-agent
sudo apt-get install -y "./$agent_deb"
join=$(api -d '{"name": "smoke-pkg", "serverAddress": "127.0.0.1:7443"}' "$base/api/join-tokens" | jq -r .code)
printf '%s\n' "$join" | sudo centrald-agent enroll --key-stdin
systemctl is-active centrald-agent
test ! -e /etc/systemd/system/centrald-agent.service
wait_for "packaged device online" test "$(online_count)" = 1

step "purge removes services, credentials, and data"
sudo apt-get purge -y centrald-agent centrald-server
if systemctl is-active --quiet centrald-server; then exit 1; fi
test ! -e /etc/centrald/agent.toml
test ! -e /var/lib/centrald

echo
echo "package smoke test passed"
