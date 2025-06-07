#!/usr/bin/env bash

#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Make a few environment variables immediately immutable
declare -r HOME="$HOME"
declare -r XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR"
declare -r XAUTHORITY="$XAUTHORITY"
declare -r XDG_SESSION_TYPE="$XDG_SESSION_TYPE"
declare -rx PATH="/bin:/usr/bin"

# If we have nothing, do nothing
[[ ! "$1" || ! "$2" ]] && echo "ERROR: no params provided" && exit 1

# Determine what kind of thing we are running
declare EXEC_TYPE="unknown"
case "$1" in
	--help|-h)
		echo "Help Statement"
		exit 0
		;;
	--command|-c)
		EXEC_TYPE="command"
		;;
	--file|-f)
		EXEC_TYPE="file"
		;;
	*)
		echo "ERROR: '$1' unrecognized argument"
		exit 1
		;;
esac

# Command variables
declare -r EXEC="$2"
declare -r EXEC_ARGS="${@:3}"
declare -r BWRAP_BIN="/usr/bin/bwrap"
declare BWRAP_ARGS="--cap-drop ALL"
declare EXEC_NAME="$2"

# Prints the contents of $1 in an nl separated list
# - converts if from comma separated to nl separated
function params_list() {
	echo "$1" | tr "," '\n'
}

# PACKAGE and USER do the same thing
# - APPLICATION is supposed to be predefined by the app and not changed
# - USER is for user overrides
declare -r SANDBOX_PARAMS="$(params_list "$SB_APPLICATION_SANDBOX_PARAMS,$SB_USER_SANDBOX_PARAMS")"

# Directory/device access vars
declare -r HOME_ACCESS="$(params_list $SB_HOME_RW_ACCESS)" # HOME relative rw access paths
declare -r RO_ACCESS="$(params_list $SB_RO_ACCESS)" # any path granted read-only
declare -r DEV_ACCESS="$(params_list $SB_DEV_ACCESS)" # grants access to any device in /dev
declare -r SOCKET_ACCESS="$(params_list $SB_SOCKET_ACCESS)" # XDG_RUNTIME_DIR relative socket access

# Figure out what window system we are using
declare WINDOW_SYSTEM="${SB_WINDOW_SYSTEM:-$XDG_SESSION_TYPE}"
if [[ "$WINDOW_SYSTEM" != "none" && "$WINDOW_SYSTEM" != "any" &&
      "$WINDOW_SYSTEM" != "x11" && "$WINDOW_SYSTEM" != "wayland" ]]; then
	WINDOW_SYSTEM="$XDG_SESSION_TYPE"
fi

# Checks if a specific param is present in the params list
function sandbox_param_present() {
	echo "$SANDBOX_PARAMS" | grep -F -x "$1"
}
# Sandbox parsing logic
# - By default all protections should be on
# - If a specific protection is enabled via params, it enforced
# - Params `sandbox` and `nosandbox` are essentially defaults control
# - `nosandbox` will switch the default from on-by-default to off-by-default
# - `sandbox` will switch to enforce-by-default, which will present all bypass
function sandbox_param_enabled() {
	[[ -z "$(sandbox_param_present "no$1")" && -z "$(sandbox_param_present "nosandbox")" ]] && echo "$1"
	[[ -n "$(sandbox_param_present "$1")" || -n "$(sandbox_param_present "sandbox")" ]] && echo "$1"
}
# Similar to sandbox_param_enabled except it is off by default and is used for grants rather than restrictions
# - denying is enforced
function sandbox_param_allowed() {
	if [[ -z "$(sandbox_param_present "no$1")" && -z "$(sandbox_param_present "sandbox")" ]]; then
		[[ -n "$(sandbox_param_present "$1")" ]] && echo "$1"
	fi
}

# Some general purpose access functions
declare NULLIFY_DIRS="/"
function raw_grant() {
	BWRAP_ARGS+=" --bind-try $1 $1" # unfiltered grant, avoid usage if possible
}
function grant_ro_access() {
	BWRAP_ARGS+=" --ro-bind-try $1 $1"
}
function clear_dir() {
	BWRAP_ARGS+=" --perms 555 --tmpfs $1"
}
function grant_device_access() {
	BWRAP_ARGS+=" --dev-bind-try /dev/$1 /dev/$1"
}
function nullify_file() {
	BWRAP_ARGS+=" --ro-bind-try /dev/null $1"
}
function nullify_dir() {
	clear_dir "$1" && NULLIFY_DIRS+=",$1"
}
function grant_home_rw_access() {
	raw_grant "$HOME/$1"
}
function grant_socket_access() {
	grant_ro_access "$XDG_RUNTIME_DIR/$1"
}

# General sandbox function
function determine_sandbox_args() {
	local -r IS_EPHEMERAL="$(sandbox_param_allowed "ephemeral")"
	
	# allow everything with no sandbox
	[[ -n "$(sandbox_param_present "nosandbox")" ]] && BWRAP_ARGS+=" --dev-bind / /"
	BWRAP_ARGS+=" --unshare-user"
	BWRAP_ARGS+=" --unshare-cgroup"
	[[ -n "$(sandbox_param_enabled "unshareuts")" ]] && BWRAP_ARGS+=" --unshare-uts --hostname sandbox"
	[[ -n "$(sandbox_param_enabled "unsharenetwork")" ]] && BWRAP_ARGS+=" --unshare-net"
	[[ -n "$(sandbox_param_enabled "newsession")" ]] && BWRAP_ARGS+=" --new-session"
	
	# /proc & process access
	BWRAP_ARGS+=" --proc /proc"
	[[ -n "$(sandbox_param_enabled "unshareprocesses")" ]] && BWRAP_ARGS+=" --unshare-pid"
	
	### GROUP_RO_ACCESS
	# prevent system ld preload
	[[ -n "$(sandbox_param_enabled "preventpreload")" ]] && nullify_file "/etc/ld.so.preload"
	# /usr access
	if [[ -n "$(sandbox_param_enabled "hideusr")" ]]; then
		nullify_dir "/usr"
	else
		grant_ro_access "/usr"
	fi
	# /bin access
	if [[ -n "$(sandbox_param_enabled "hidebin")" ]]; then
		nullify_dir "/usr/bin"
	else
		grant_ro_access "/usr/bin"
	fi
	# /sbin access
	if [[ -n "$(sandbox_param_enabled "hidesbin")" ]]; then
		nullify_dir "/usr/sbin"
	else
		grant_ro_access "/usr/sbin"
	fi
	# /libexec access
	if [[ -n "$(sandbox_param_enabled "hidelibexec")" ]]; then
		nullify_dir "/usr/libexec"
	else
		grant_ro_access "/usr/libexec"
	fi
	# /lib64 and /lib access
	grant_ro_access "/usr/lib64"
	grant_ro_access "/usr/lib"
	# On Fedora, these dirs are symlinked
	BWRAP_ARGS+=" --symlink /usr/bin /bin"
	BWRAP_ARGS+=" --symlink /usr/sbin /sbin"
	BWRAP_ARGS+=" --symlink /usr/lib64 /lib64"
	BWRAP_ARGS+=" --symlink /usr/lib /lib"
	# /etc access
	if [[ -n "$(sandbox_param_enabled "hideetc")" ]]; then
		nullify_dir "/etc"
	else
		grant_ro_access "/etc"
	fi
	# /tmp access
	if [[ -n "$(sandbox_param_enabled "hidetmp")" || -n "$IS_EPHEMERAL" ]]; then
		clear_dir "/tmp"
	else
		raw_grant "/tmp"
	fi
	# /sys access
	if [[ -n "$(sandbox_param_enabled "hidesys")" ]]; then
		nullify_dir "/sys"
	else
		grant_ro_access "/sys"
	fi
	# /run access
	if [[ -n "$(sandbox_param_enabled "hiderun")" ]]; then
		nullify_dir "/run"
		[[ -z "$(sandbox_param_enabled "unsharenetwork")" ]] && grant_ro_access "/run/systemd/resolve"
	else
		grant_ro_access "/run"
	fi
	# /var access
	if [[ -n "$(sandbox_param_enabled "hidevar")" ]]; then
		nullify_dir "/var"
	else
		grant_ro_access "/var"
	fi
	# custom defined access
	for path in $RO_ACCESS; do
		grant_ro_access "$path"
	done
	### END_GROUP_RO_ACCESS
	
	### GROUP_SOCKET_ACCESS
	# XDG_RUNTIME_DIR access
	if [[ -n "$(sandbox_param_enabled "hidesockets")" ]]; then
		nullify_dir "$XDG_RUNTIME_DIR"
	else
		grant_ro_access "$XDG_RUNTIME_DIR"
	fi
	# pipewire access
	[[ -n "$(sandbox_param_allowed "allowpipewire")" ]] && grant_socket_access "pipewire-0"
	# pulseaudio access
	[[ -n "$(sandbox_param_allowed "allowpulseaudio")" ]] && grant_socket_access "pulse"
	# dconf access
	if [[ -n "$(sandbox_param_allowed "allowdconf")" ]]; then
		if [[ -n "$IS_EPHEMERAL" ]]; then
			grant_socket_access "dconf"
		else
			raw_grant "$XDG_RUNTIME_DIR/dconf"
		fi
	fi
	# custom defined access
	for socket in $SOCKET_ACCESS; do
		grant_socket_access "$socket"
	done
	### END_GROUP_SOCKET_ACCESS
	
	### GROUP_DEVICE_ACCESS
	# /dev access
	if [[ -n "$(sandbox_param_enabled "hidedevices")" ]]; then
		BWRAP_ARGS+=" --dev /dev"
	else
		BWRAP_ARGS+=" --dev-bind /dev /dev"
	fi
	# gpu access
	[[ -n "$(sandbox_param_allowed "allowgpu")" ]] && grant_device_access "dri"
	# usb access
	[[ -n "$(sandbox_param_allowed "allowusb")" ]] && grant_device_access "usb"
	# shared memory access
	if [[ -n "$(sandbox_param_allowed "allowshm")" ]]; then
		grant_device_access "shm"
	else
		nullify_dir "/dev/shm"
	fi
	# custom defined access
	for device in $DEVICE_ACCESS; do
		grant_device_access "$device"
	done
	### END_GROUP_DEVICE_ACCESS
	
	### GROUP_HOME_RW_ACCESS
	if [[ -n "$IS_EPHEMERAL" ]]; then
		clear_dir "$HOME"
	elif [[ -n "$(sandbox_param_enabled "protecthome")" ]]; then
		grant_ro_access "$HOME"
	else
		raw_grant "$HOME"
	fi
	# downloads access
	if [[ -n "$(sandbox_param_allowed "allowdownloads")" ]]; then
		if [[ -n "$IS_EPHEMERAL" ]]; then
			grant_ro_access "$HOME/Downloads"
		else
			grant_home_rw_access "Downloads"
		fi
	fi
	# custom defined access
	for path in $HOME_RW_ACCESS; do
		if [[ -n "$IS_EPHEMERAL" ]]; then
			grant_ro_access "$HOME/$path"
		else
			grant_home_rw_access "$path"
		fi
	done
	### END_GROUP_HOME_RW_ACCESS
	
	### GROUP_X11_WAYLAND_ACCESS
	# x11 socket access
	if [[ "$WINDOW_SYSTEM" == "x11" || "$WINDOW_SYSTEM" == "any" ]]; then
		grant_ro_access "$XAUTHORITY"
		grant_ro_access "/tmp/.X11-unix"
	else
		BWRAP_ARGS+=" --unsetenv DISPLAY"
		BWRAP_ARGS+=" --unsetenv XAUTHORITY"
		nullify_file "$XAUTHORITY"
		nullify_dir "/tmp/.X11-unix"
	fi
	# wayland socket access
	if [[ "$WINDOW_SYSTEM" == "wayland" || "$WINDOW_SYSTEM" == "any" ]]; then
		grant_socket_access "wayland-0"
	else
		BWRAP_ARGS+=" --unsetenv WAYLAND_DISPLAY"
		nullify_file "$XDG_RUNTIME_DIR/wayland-0"
	fi
	### END_GROUP_X11_WAYLAND_ACCESS
	
	### GROUP_DBUS_ACCESS
	if [[ -n "$(sandbox_param_allowed "allowdbus")" ]]; then
		grant_ro_access "/run/dbus/system_bus_socket"
		grant_socket_access "bus"
	fi
	# TODO: Implement xdg-dbus-proxy
	### END_GROUP_DBUS_ACCESS
	
	# Grant access to the binary
	case "$EXEC_TYPE" in
		command)
			EXEC_NAME="/usr/bin/$EXEC"
			;;
		file)
			EXEC_NAME="$EXEC"
			;;
		*)
			echo "ERROR: exec type '$EXEC_TYPE' unknown"
			exit 0
			;;
	esac
	grant_ro_access "$EXEC_NAME"
	
	# mount all nullified dirs read-only
	# we do this after to allow mounting into those dirs
	if [[ -n "$NULLIFY_DIRS" ]]; then
		NULLIFY_DIRS="$(params_list "$NULLIFY_DIRS")"
		for dir in $NULLIFY_DIRS; do
			BWRAP_ARGS+=" --remount-ro $dir"
		done
	fi
}

determine_sandbox_args

BWRAP_ARGS+=" --"

echo "$EXEC_NAME $BWRAP_BIN $BWRAP_ARGS $EXEC $EXEC_ARGS"

exec -a "$EXEC_NAME" $BWRAP_BIN $BWRAP_ARGS "$EXEC" $EXEC_ARGS
