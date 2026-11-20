#!/bin/sh
# CentralD agent installer for Linux.
#
# The web app shows the full command, which pins this server's TLS key and
# passes the one-time join code through the environment (never as an
# argument):
#
#   curl -fsSk --pinnedpubkey 'sha256//…' https://SERVER/install.sh | CENTRALD_JOIN='cdj1.…' sh
#
# Set CENTRALD_MONITOR_ONLY=1 to enroll a device that reports status but
# refuses commands and terminals.
set -eu

SERVER='__CENTRALD_SERVER__'
PIN='__CENTRALD_PIN__'

fail() {
	printf 'centrald: %s\n' "$*" >&2
	exit 1
}

main() {
	[ -n "${CENTRALD_JOIN:-}" ] ||
		fail "CENTRALD_JOIN is not set. Copy the whole command from the CentralD web app."
	[ "$(uname -s)" = Linux ] || fail "this installer is for Linux only."
	case "$(uname -m)" in
	x86_64 | amd64) arch=x86_64 ;;
	aarch64 | arm64) arch=aarch64 ;;
	*) fail "unsupported CPU architecture: $(uname -m)" ;;
	esac

	if [ "$(id -u)" -eq 0 ]; then
		sudo=
	elif command -v sudo >/dev/null 2>&1; then
		sudo=sudo
		printf 'centrald: installing needs root; sudo may ask for your password.\n'
	else
		fail "run this as root, or install sudo first."
	fi

	if [ -x /usr/bin/centrald-agent ]; then
		# Installed from a distribution package: use it as is.
		agent=/usr/bin/centrald-agent
	else
		command -v curl >/dev/null 2>&1 || fail "curl is required."
		tmp=$(mktemp -d)
		trap 'rm -rf "$tmp"' EXIT INT TERM
		url="https://$SERVER/download/agent/linux/$arch"
		printf 'centrald: downloading the agent from %s\n' "$SERVER"
		curl -fsSk --pinnedpubkey "$PIN" -o "$tmp/centrald-agent" "$url" ||
			fail "download failed. The server may not offer a $arch Linux agent; see its Settings page."
		expected=$(curl -fsSk --pinnedpubkey "$PIN" "$url.sha256") ||
			fail "could not fetch the agent checksum."
		actual=$(sha256sum "$tmp/centrald-agent" | cut -d' ' -f1)
		[ "$expected" = "$actual" ] || fail "the downloaded agent is corrupt (checksum mismatch)."
		$sudo install -d -m 0755 /usr/local/bin
		$sudo install -m 0755 "$tmp/centrald-agent" /usr/local/bin/centrald-agent.new
		$sudo mv -f /usr/local/bin/centrald-agent.new /usr/local/bin/centrald-agent
		agent=/usr/local/bin/centrald-agent
	fi

	if [ "${CENTRALD_MONITOR_ONLY:-}" = 1 ]; then
		printf '%s\n' "$CENTRALD_JOIN" | $sudo "$agent" enroll --key-stdin --monitor-only
	else
		printf '%s\n' "$CENTRALD_JOIN" | $sudo "$agent" enroll --key-stdin
	fi
}

# Everything runs from main so a partial download never executes.
main "$@"
