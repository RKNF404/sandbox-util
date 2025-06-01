#!/usr/bin/env bash

[[ ! "$1" ]] && echo "ERROR: no params provided" && exit 1

declare -r HOME="$HOME"
declare -r XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR"
declare -r XAUTHORITY="$XAUTHORITY"
declare -r XDG_SESSION_TYPE="$XDG_SESSION_TYPE"

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
	echo "Help Statement"
	exit 0
fi

# Command variables
declare -r COMMAND="$1"
declare -r COMMAND_ARGS="${@:2}"
declare -r BWRAP_BIN="/usr/bin/bwrap"
declare BWRAP_ARGS="--cap-drop ALL"

# Prints the contents of $1 in an nl separated list
# - converts if from comma separated to nl separated
function params_list() {
	echo "$1" | tr "," '\n'
}

# PACKAGE and USER do the same thing
# - APPLICATION is supposed to be predefined by the app or not changed
# - USER is for user overrides
declare -r SANDBOX_PARAMS="$(params_list $(params_list $SB_APPLICATION_SANDBOX_PARAMS),$(params_list $SB_USER_SANDBOX_PARAMS))"
echo "$SANDBOX_PARAMS"

# Directory/device access vars
declare -r HOME_ACCESS="$(params_list $SB_HOME_RW_ACCESS)" # HOME relative rw access paths
declare -r RO_ACCESS="$(params_list $SB_RO_ACCESS)" # any path granted read-only
declare -r DEV_ACCESS="$(params_list $SB_DEV_ACCESS)" # grants access to any device in /dev
declare -r SOCKET_ACCESS="$(params_list $SB_SOCKET_ACCESS)" # XDG_RUNTIME_DIR relative socket access

# Figure out what window system we need to use
declare WINDOW_SYSTEM="${SB_WINDOWING_SYSTEM:-$XDG_SESSION_TYPE}"
if [[ "$WINDOW_SYSTEM" != "none" && "$WINDOW_SYSTEM" != "any" &&
      "$WINDOW_SYSTEM" != "x11" && "$WINDOW_SYSTEM" != "wayland" ]]; then
	WINDOW_SYSTEM="$XDG_SESSION_TYPE"
fi

# Checks if a specific param is present in the params list
function sandbox_param_present() {
	echo "$SANDBOX_PARAMS" | grep -F -x -q "$1"
}
# Sandbox parsing logic
# - By default all protections should be on
# - If a specific protection is enabled via params, it enforced
# - Params `sandbox` and `nosandbox` are essentially defaults control
# - `nosandbox` will switch the default from on-by-default to off-by-default
# - `sandbox` will switch to enforce-by-default, which will present all bypass
function sandbox_param_enabled() {
	! sandbox_param_present "no$1" && ! sandbox_param_present "nosandbox" && echo "$1"
	sandbox_param_present "$1" || sandbox_param_present "sandbox"
}
# Similar to sandbox_param_enabled except it is off by default and is used for grants rather than restrictions
# - denying is enforced
function sandbox_param_allowed() {
	! sandbox_param_present "no$1" && sandbox_param_present "$1"
}

# Some general purpose access functions
function raw_grant() {
	[[ -f "$1" || -d "$1" ]] && BWRAP_ARGS+=" --bind $1 $1" # unfiltered grant, avoid usage if possible
}
function grant_ro_access() {
	[[ -f "$1" || -d "$1" ]] && BWRAP_ARGS+=" --ro-bind $1 $1"
}
function clear_dir() {
	[[ -d "$1" ]] && BWRAP_ARGS+=" --tmpfs $1"
}
function grant_device_access() {
	[[ -f "$1" || -d "$1" ]] && BWRAP_ARGS+=" --dev-bind /dev/$1 /dev/$1"
}
function nullify_file() {
	[[ -f "$1" ]] && BWRAP_ARGS+=" --ro-bind /dev/null $1"
}
function nullify_dir() {
	[[ -d "$1" ]] && BWRAP_ARGS+=" --perms 444" && clear_dir "$1"
}
function grant_home_rw_access() {
	[[ -f "$1" || -d "$1" ]] && raw_grant "$HOME/$1"
}
function grant_socket_access() {
	[[ -f "$1" || -d "$1" ]] && grant_ro_access "$XDG_RUNTIME_DIR/$1"
}

# WIP BELOW
function determine_sandbox_args() {
	local -r IS_EPHEMERAL="$(sandbox_param_allowed "ephemeral")"
	
	# allow everything with no sandbox
	sandbox_param_present "nosandbox" >/dev/null && BWRAP_ARGS+=" --dev-bind / /"
	BWRAP_ARGS+=" --unshare-user-try"
	BWRAP_ARGS+=" --unshare-cgroup-try"
	sandbox_param_enabled "unshareuts" >/dev/null && BWRAP_ARGS+=" --unshare-uts --hostname secureblue"
	sandbox_param_enabled "unsharenetwork" >/dev/null && BWRAP_ARGS+=" --unshare-net"
	sandbox_param_enabled "newsession" >/dev/null && BWRAP_ARGS+=" --new-session"
	
	### GROUP_RO_ACCESS
	# prevent system ld preload
	sandbox_param_enabled "preventpreload" >/dev/null && nullify_file "/etc/ld.so.preload"
	# /proc and process access
	BWRAP_ARGS+=" --proc /proc"
	if sandbox_param_enabled "hideprocesses" >/dev/null; then
		BWRAP_ARGS+=" --unshare-pid"
	fi
	# /bin access
	if sandbox_param_enabled "hidebin" >/dev/null; then
		#nullify_dir "/bin"
		grant_ro_access "$BWRAP_BIN"
		grant_ro_access "/bin/$COMMAND"
	else
		grant_ro_access "/bin"
	fi
	# /sbin access
	if sandbox_param_enabled "hidesbin" >/dev/null; then
		nullify_dir "/sbin"
		grant_ro_access "/sbin/$COMMAND"
		echo "lmao"
	else
		grant_ro_access "/sbin"
	fi
	# /etc access
	if sandbox_param_enabled "hideetc" >/dev/null; then
		nullify_dir "/etc"
	else
		grant_ro_access "/etc"
	fi
	# /lib64 and /lib access
	if sandbox_param_enabled "hidelib" >/dev/null; then
		nullify_dir "/lib64"
		nullify_dir "/lib"
	else
		grant_ro_access "/lib64"
		grant_ro_access "/lib"
	fi
	# /tmp access
	if sandbox_param_enabled "hidetmp" >/dev/null || [[ "$IS_EPHEMERAL" ]]; then
		clear_dir "/tmp"
	else
		raw_grant "/tmp"
	fi
	# /sys access
	if sandbox_param_enabled "hidesys" >/dev/null; then
		nullify_dir "/sys"
	else
		grant_ro_access "/sys"
	fi
	# /run access
	if sandbox_param_enabled "hiderun" >/dev/null; then
		nullify_dir "/run"
		! sandbox_param_enabled "unsharenetwork" >/dev/null && grant_ro_access "/run/systemd/resolve"
	else
		grant_ro_access "/run"
	fi
	# /home access
	if sandbox_param_enabled "hideallhome" >/dev/null; then
		nullify_dir "/home"
	else
		grant_ro_access "/home"
	fi
	# /var access
	if sandbox_param_enabled "hidevar" >/dev/null; then
		nullify_dir "/var"
	else
		grant_ro_access "/var"
	fi
	# /usr access
	if sandbox_param_enabled "hideusr" >/dev/null; then
		nullify_dir "/usr"
	else
		grant_ro_access "/usr"
	fi
	# custom defined access
	for path in "$RO_ACCESS"; do
		grant_ro_access "$path"
	done
	### END_GROUP_RO_ACCESS
	
	### GROUP_SOCKET_ACCESS
	# XDG_RUNTIME_DIR access
	if sandbox_param_enabled "hidesockets" >/dev/null; then
		nullify_dir "$XDG_RUNTIME_DIR"
	else
		grant_ro_access "$XDG_RUNTIME_DIR"
	fi
	# pipewire access
	sandbox_param_allowed "allowpipewire" && grant_socket_access "pipewire-0"
	# pulseaudio access
	sandbox_param_allowed "allowpulseaudio" && grant_socket_access "pulse"
	if sandbox_param_allowed "allowdconf" >/dev/null; then
		if [[ "$IS_EPHEMERAL" ]]; then
			grant_socket_access "dconf"
		else
			raw_grant "$XDG_RUNTIME_DIR/dconf"
		fi
	fi
	# custom defined access
	for socket in "$SOCKET_ACCESS"; do
		grant_socket_access "$socket"
	done
	### END_GROUP_SOCKET_ACCESS
	
	### GROUP_DEVICE_ACCESS
	# /dev access
	if sandbox_param_enabled "hidedevices" >/dev/null; then
		BWRAP_ARGS+=" --dev /dev"
	else
		BWRAP_ARGS+=" --dev-bind /dev /dev"
	fi
	# gpu access
	sandbox_param_allowed "allowgpu" >/dev/null && grant_device_access "dri"
	# usb access
	sandbox_param_allowed "allowusb" >/dev/null && grant_device_access "usb"
	# custom defined access
	for device in "$DEVICE_ACCESS"; do
		grant_device_access "$device"
	done
	### END_GROUP_DEVICE_ACCESS
	
	### GROUP_HOME_RW_ACCESS
	if [[ "$IS_EPHEMERAL" ]]; then
		clear_dir "$HOME"
	elif sandbox_param_enabled "protecthome" >/dev/null; then
		grant_ro_access "$HOME"
	else
		raw_grant "$HOME"
	fi
	# downloads folder access
	if sandbox_param_allowed "allowdownloads" >/dev/null; then
		if [[ "$IS_EPHEMERAL" ]]; then
			grant_ro_access "$HOME/Downloads"
		else
			grant_home_rw_access "Downloads"
		fi
	fi
	# custom defined access
	for path in "$HOME_RW_ACCESS"; do
		if [[ "$IS_EPHEMERAL" ]]; then
			grant_ro_access "$HOME/$path"
		else
			grant_device_access "$path"
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
		nullify_dir "/tmp/.X11-unix"
	fi
	# wayland socket access
	if [[ "$WINDOW_SYSTEM" == "wayland" || "$WINDOW_SYSTEM" == "any" ]]; then
		grant_socket_access "wayland-0"
	else
		nullify_file "$XDG_RUNTIME_DIR/wayland-0"
	fi
	### END_GROUP_X11_WAYLAND_ACCESS
	
	### GROUP_DBUS_ACCESS
	if sandbox_param_enabled "denydbus" >/dev/null; then
		grant_ro_access "/run/dbus/system_bus_socket"
		grant_socket_access "bus"
	fi
	### END_GROUP_DBUS_ACCESS
}

determine_sandbox_args

BWRAP_ARGS+=" --"

echo "$BWRAP_BIN $BWRAP_ARGS $COMMAND $COMMAND_ARGS"

exec -a "$COMMAND" $BWRAP_BIN $BWRAP_ARGS "$COMMAND" $COMMAND_ARGS
