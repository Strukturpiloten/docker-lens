"""Unexecuted outer-bootstrap description and private, unauthenticated frame decoder.

No lifecycle receipt, harness wiring, native qualification, or admission is supplied.
The shell description assumes dash/BusyBox ash dynamic function-local scope and
the image's existing stat -L -c and readlink tools;
their actual behavior remains to be qualified separately on every exact image.
"""

from datetime import datetime
import json
import re

MARKER = b"DOCKERLENS_OUTER_BOOTSTRAP_V1"
MAX_LOG_BYTES = 16384
MAX_FRAME_BYTES = 1024
U64 = (1 << 64) - 1
U32 = (1 << 32) - 1

# This is data, never executed by this module or its component tests. Functions
# run in the original shell, not a subshell: /proc/self must identify PID1.
# Only the normal bootstrap invocation suppresses stderr, not the eventual exec.
# A final exec failure remains private startup-log output, not observation proof.
BOOTSTRAP = r'''fail() { exit 73; }
uint() {
    number=$1 bound=$2
    case "$number" in ''|*[!0-9]*|0?*) fail;; esac
    [ "${#number}" -le "${#bound}" ] || fail
    if [ "${#number}" -eq "${#bound}" ]; then
        while [ -n "$number" ]; do
            digit=${number%"${number#?}"} ceiling=${bound%"${bound#?}"}
            [ "$digit" -le "$ceiling" ] || fail
            [ "$digit" -eq "$ceiling" ] || break
            number=${number#?} bound=${bound#?}
        done
    fi
}
positive() { uint "$1" 18446744073709551615; [ "$1" != 0 ] || fail; }
namespace() {
    link=$(command readlink "$1") || fail
    [ "${#link}" -le 64 ] || fail
    ns=${link#*\[} ns=${ns%\]}
    positive "$ns"
    [ "$link" = "$2:[$ns]" ] || fail
}
observe_identity() {
    [ "$$" = 1 ] || fail
    pid_count=0 nspid_count=0 rows=0 bytes=0
    while :; do
        line=
        if IFS= read -r line; then :; else [ -z "$line" ] || fail; break; fi
        rows=$((rows + 1)) bytes=$((bytes + ${#line} + 1))
        [ "$rows" -le 128 ] && [ "${#line}" -le 1024 ] && [ "$bytes" -le 16384 ] || fail
        case "$line" in
            Pid:*|NSpid:*)
                field=${line%%:*} value=${line#*:}
                IFS=' 	' read -r first extra <<EOF
$value
EOF
                [ "$first" = 1 ] && [ -z "$extra" ] || fail
                case "$field" in Pid) pid_count=$((pid_count + 1));; NSpid) nspid_count=$((nspid_count + 1));; esac;;
        esac
    done < /proc/self/status
    [ "$pid_count" = 1 ] && [ "$nspid_count" = 1 ] || fail
    uid_count=0 rows=0 bytes=0
    while :; do
        line=
        if IFS= read -r line; then :; else [ -z "$line" ] || fail; break; fi
        rows=$((rows + 1)) bytes=$((bytes + ${#line} + 1))
        [ "$rows" -le 128 ] && [ "${#line}" -le 1024 ] && [ "$bytes" -le 16384 ] || fail
        case "$line" in Uid:*)
            value=${line#*:}
            IFS=' 	' read -r uid effective saved filesystem extra <<EOF
$value
EOF
            uint "$uid" 4294967295
            [ "$uid" = "$effective" ] && [ "$uid" = "$saved" ] && [ "$uid" = "$filesystem" ] && [ -z "$extra" ] || fail
            uid_count=$((uid_count + 1));;
        esac
    done < /proc/1/status
    [ "$uid_count" = 1 ] || fail
    exec 3< /proc/1/stat || fail
    IFS= read -r line <&3 || fail
    if IFS= read -r extra <&3; then fail; fi
    [ -z "$extra" ] || fail
    exec 3<&- || fail
    [ "${#line}" -le 4096 ] || fail
    case "$line" in '1 ('*') '*) ;; *) fail;; esac
    tail=${line##*) }
    IFS=' ' read -r state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice threads itreal start rest <<EOF
$tail
EOF
    positive "$start"
    namespace /proc/1/ns/pid pid; pidns=$ns
    namespace /proc/1/ns/mnt mnt; mountns=$ns
    namespace /proc/1/ns/cgroup cgroup; cgroupns=$ns
}
observe_membership() {
    rows=0
    while :; do
        line=
        if IFS= read -r line; then :; else [ -z "$line" ] || fail; break; fi
        rows=$((rows + 1))
        [ "$rows" = 1 ] && [ "$line" = '0::/' ] || fail
    done < /proc/1/cgroup
    [ "$rows" = 1 ] || fail
}
mount_optional() {
    case "$1" in *[!a-z0-9_:]*) fail;; esac
    case "$1" in
        shared:*|master:*|propagate_from:*) positive "${1#*:}";;
        unbindable) :;;
        *) fail;;
    esac
}
mount_target() {
    # A directory identity cannot authenticate a controller file hidden by a
    # child overmount. Never follow a split mapping below the observed root.
    case "$2" in
        /sys/fs/cgroup/*) fail;;
        /sys/fs/cgroup) [ "$1" = cgroup2 ] || fail;;
    esac
}
observe_mount() {
    rows=0 bytes=0 matches=0
    non_ascii='*[! -~]*'
    while :; do
        line=
        if IFS= read -r line; then :; else [ -z "$line" ] || fail; break; fi
        rows=$((rows + 1)) bytes=$((bytes + ${#line} + 1))
        [ "$rows" -le 256 ] && [ "${#line}" -le 4096 ] && [ "$bytes" -le 16384 ] || fail
        case "$line" in $non_ascii|*\\*) fail;; esac
        IFS=' ' read -r mid parent device root point options remaining <<EOF
$line
EOF
        positive "$mid"; positive "$parent"
        major=${device%%:*} minor=${device#*:}
        uint "$major" 4294967295; uint "$minor" 4294967295
        [ "$device" = "$major:$minor" ] || fail
        case "$root" in /*) ;; *) fail;; esac
        case "$point" in /*) ;; *) fail;; esac
        case "$line" in *' - '*) ;; *) fail;; esac
        before=${line%% - *}
        header="$mid $parent $device $root $point $options"
        if [ "$before" != "$header" ]; then
            case "$before" in "$header "*) optional=${before#"$header "};; *) fail;; esac
            # Validate before splitting; no wildcard or shell input can expand.
            case "$optional" in *[!a-z0-9_:\ ]*|' '|''|*'  '*) fail;; esac
            while :; do
                optional_field=${optional%% *}
                mount_optional "$optional_field"
                case "$optional" in *' '*) optional=${optional#* };; *) break;; esac
            done
        fi
        after=${line#* - }
        case "$after" in *' - '*) fail;; esac
        IFS=' ' read -r kind source super extra <<EOF
$after
EOF
        [ -n "$options" ] && [ -n "$source" ] && [ -n "$super" ] && [ -z "$extra" ] || fail
        mount_target "$kind" "$point"
        case "$kind" in
            cgroup) fail;;
            cgroup2)
                matches=$((matches + 1))
                [ "$matches" = 1 ] && [ "$major" = 0 ] && [ "$root" = / ] && [ "$point" = /sys/fs/cgroup ] || fail
                mount_id=$mid parent_id=$parent mount_device=$device mount_minor=$minor;;
        esac
    done < /proc/1/mountinfo
    [ "$matches" = 1 ] || fail
}
root_stat() {
    [ -d "$1" ] || fail
    case "$1" in /sys/fs/cgroup) [ ! -L "$1" ] || fail;; /proc/1/fd/9) :;; *) fail;; esac
    record=$(command stat -L -c '%d %i' "$1") || fail
    [ "${#record}" -le 64 ] || fail
    IFS=' ' read -r device inode extra <<EOF
$record
EOF
    positive "$device"; positive "$inode"
    [ "$record" = "$device $inode" ] && [ -z "$extra" ] || fail
    expected_device=$(( (mount_minor & 255) | ((mount_minor & 4294967040) << 12) ))
    [ "$device" = "$expected_device" ] || fail
}
controller_value() {
    exec 3< "/proc/1/fd/9/$1" || fail
    IFS= read -r scalar <&3 || fail
    [ "$scalar" = "$2" ] || fail
    if IFS= read -r extra <&3; then fail; fi
    [ -z "$extra" ] || fail
    exec 3<&- || fail
}
bootstrap() {
    # dash and BusyBox ash provide dynamic local scope. Helper assignments and
    # read targets must restore preexisting exported values before the exec tail.
    local IFS nonce number bound digit ceiling link ns pid_count nspid_count rows bytes || fail
    local line field value first extra uid_count uid effective saved filesystem tail || fail
    local state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt || fail
    local utime stime cutime cstime priority nice threads itreal start rest pidns mountns cgroupns || fail
    local matches non_ascii mid parent device root point options remaining major minor || fail
    local before header optional optional_field after kind source super mount_id parent_id mount_device mount_minor || fail
    local record inode expected_device scalar initial_start initial_uid initial_pidns initial_mountns initial_cgroupns || fail
    local initial_mount_id initial_parent_id initial_mount_device initial_device initial_inode || fail
    nonce=$1
    case "$nonce" in *[!0-9a-f]*) fail;; esac
    [ "${#nonce}" = 64 ] || fail
    observe_identity
    initial_start=$start initial_uid=$uid initial_pidns=$pidns initial_mountns=$mountns initial_cgroupns=$cgroupns
    observe_membership
    observe_mount
    initial_mount_id=$mount_id initial_parent_id=$parent_id initial_mount_device=$mount_device
    [ -d /sys/fs/cgroup ] && [ ! -L /sys/fs/cgroup ] || fail
    exec 9< /sys/fs/cgroup || fail
    root_stat /proc/1/fd/9
    initial_device=$device initial_inode=$inode
    root_stat /sys/fs/cgroup
    [ "$device:$inode" = "$initial_device:$initial_inode" ] || fail
    controller_value pids.max 512
    controller_value memory.max 4294967296
    root_stat /proc/1/fd/9
    [ "$device:$inode" = "$initial_device:$initial_inode" ] || fail
    root_stat /sys/fs/cgroup
    [ "$device:$inode" = "$initial_device:$initial_inode" ] || fail
    observe_membership
    observe_mount
    [ "$mount_id:$parent_id:$mount_device" = "$initial_mount_id:$initial_parent_id:$initial_mount_device" ] || fail
    observe_identity
    [ "$start:$uid:$pidns:$mountns:$cgroupns" = "$initial_start:$initial_uid:$initial_pidns:$initial_mountns:$initial_cgroupns" ] || fail
    printf 'DOCKERLENS_OUTER_BOOTSTRAP_V1 {"contract":"outer-bootstrap-v1","nonce":"%s","pid":1,"proc_pid":1,"nspid":[1],"start":%s,"uid":%s,"namespaces":[%s,%s,%s],"membership":"0::/","mount":[%s,%s,"%s","/","/sys/fs/cgroup"],"controller":[%s,%s,512,4294967296]}\n' "$nonce" "$start" "$uid" "$pidns" "$mountns" "$cgroupns" "$mount_id" "$parent_id" "$mount_device" "$initial_device" "$initial_inode" || fail
    exec 9<&- || fail
}
[ "$#" -ge 2 ] || exit 73
bootstrap "$1" 2>/dev/null
shift
exec "$@"
'''


class BootstrapError(ValueError):
    """Closed error: never include private inputs in arguments or attributes."""

    def __init__(self):
        super().__init__("outer bootstrap input refused")


def _nonce(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise BootstrapError()


def build_bootstrap_argv(nonce, original_argv):
    """Describe a wrapper; preserve the original argument list byte-for-byte."""
    _nonce(nonce)
    if type(original_argv) is not list or not 1 <= len(original_argv) <= 16:
        raise BootstrapError()
    size = 0
    for argument in original_argv:
        if type(argument) is not str or not argument or "\0" in argument:
            raise BootstrapError()
        if len(argument) > 4096:
            raise BootstrapError()
        try:
            size += len(argument.encode("utf-8"))
        except UnicodeError:
            raise BootstrapError() from None
        if size > 4096:
            raise BootstrapError()
    return ["/bin/sh", "-c", BOOTSTRAP, "dl-outer-bootstrap", nonce, *original_argv]


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BootstrapError()
        result[key] = value
    return result


def _reject_constant(_value):
    raise BootstrapError()


def _integer(value, minimum=1, maximum=U64):
    return type(value) is int and minimum <= value <= maximum


def _frame(payload, nonce):
    # Mount IDs retain the contract's u64 bound. This is not a closure-fit claim.
    if len(MARKER) + 1 + len(payload) + 1 > MAX_FRAME_BYTES:
        raise BootstrapError()
    try:
        text = payload.decode("ascii")
        data = json.loads(text, object_pairs_hook=_object, parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise BootstrapError() from None
    keys = {"contract", "nonce", "pid", "proc_pid", "nspid", "start", "uid", "namespaces", "membership", "mount", "controller"}
    if type(data) is not dict or set(data) != keys:
        raise BootstrapError()
    if data["contract"] != "outer-bootstrap-v1" or data["nonce"] != nonce or data["membership"] != "0::/":
        raise BootstrapError()
    if not _integer(data["pid"], 1, 1) or not _integer(data["proc_pid"], 1, 1):
        raise BootstrapError()
    nspid, namespaces, mount, controller = (data[key] for key in ("nspid", "namespaces", "mount", "controller"))
    if type(nspid) is not list or len(nspid) != 1 or not _integer(nspid[0], 1, 1):
        raise BootstrapError()
    if not _integer(data["start"]) or not _integer(data["uid"], 0, U32):
        raise BootstrapError()
    if type(namespaces) is not list or len(namespaces) != 3 or not all(_integer(item) for item in namespaces):
        raise BootstrapError()
    if type(mount) is not list or len(mount) != 5 or not all(_integer(item) for item in mount[:2]):
        raise BootstrapError()
    if type(mount[2]) is not str or re.fullmatch(r"0:(?:0|[1-9][0-9]{0,9})", mount[2]) is None or mount[3:] != ["/", "/sys/fs/cgroup"]:
        raise BootstrapError()
    minor = int(mount[2][2:])
    if minor > U32:
        raise BootstrapError()
    if type(controller) is not list or len(controller) != 4 or not all(_integer(item) for item in controller):
        raise BootstrapError()
    # Linux dev_t layout, not decimal minor == st_dev once minor exceeds 255.
    expected_device = (minor & 255) | ((minor & 0xffffff00) << 12)
    if controller[2:] != [512, 4294967296] or controller[0] != expected_device:
        raise BootstrapError()
    return data


_TIMESTAMP = re.compile(rb"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?(?:Z|([+-])([0-9]{2}):([0-9]{2}))")


def _timestamp(value):
    if not 20 <= len(value) <= 35:
        raise BootstrapError()
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise BootstrapError()
    try:
        datetime(*(int(match[index]) for index in range(1, 7)))
    except ValueError:
        raise BootstrapError() from None
    if match[7] is not None and (int(match[8]) > 23 or int(match[9]) > 59):
        raise BootstrapError()


def parse_bootstrap_log(raw, nonce):
    """Decode private authored bytes; no partial logical record or origin claim."""
    _nonce(nonce)
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_LOG_BYTES or not raw.endswith(b"\n"):
        raise BootstrapError()
    frame = None
    for record in raw[:-1].split(b"\n"):
        fields = record.split(b" ", 3)
        if len(fields) != 4:
            raise BootstrapError()
        timestamp, stream, tag, payload = fields
        _timestamp(timestamp)
        if stream not in (b"stdout", b"stderr") or tag != b"F":
            raise BootstrapError()
        if stream == b"stdout" and frame is None:
            if not payload.startswith(MARKER + b" "):
                raise BootstrapError()
            frame = _frame(payload[len(MARKER) + 1:], nonce)
        elif MARKER in payload:
            raise BootstrapError()
    if frame is None:
        raise BootstrapError()
    return frame
