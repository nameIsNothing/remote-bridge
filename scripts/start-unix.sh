#!/bin/sh
# USB/exFAT/noexec entrypoint. Only fixed platform filenames are read from
# SHA256SUMS; manifest text is never evaluated or used as a filesystem path.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077

fail() {
    printf '%s\n' "Remote Bridge: $*" >&2
    exit 1
}

[ "$(id -u)" != 0 ] || fail '请用日常登录账号启动；程序会在确认后请求正常 sudo 授权。'
case $0 in
    /*) launcher_path=$0 ;;
    *) launcher_path=$PWD/$0 ;;
esac
package_directory=$(CDPATH= cd -P "$(dirname "$launcher_path")" && pwd)
case $(uname -s) in
    Darwin) platform_os=darwin; default_temp=/private/tmp ;;
    Linux) platform_os=linux; default_temp=/tmp ;;
    *) fail '目前只支持 macOS 和 Linux。' ;;
esac
case $(uname -m) in
    x86_64|amd64) platform_arch=amd64 ;;
    arm64|aarch64) platform_arch=arm64 ;;
    *) fail '目前只支持 Intel/AMD x64 和 ARM64。' ;;
esac
platform=$platform_os-$platform_arch
temp_parent=${REMOTE_BRIDGE_TMPDIR:-$default_temp}
case $temp_parent in
    /*) ;;
    *) fail 'REMOTE_BRIDGE_TMPDIR 必须是本机可写且允许执行的绝对目录。' ;;
esac
[ -d "$temp_parent" ] && [ -w "$temp_parent" ] || fail "本机临时目录不可写：$temp_parent"
temp_parent=$(CDPATH= cd -P "$temp_parent" && pwd)
stage_directory=$(mktemp -d "$temp_parent/remotebridge-usb.XXXXXXXXXX") || fail '无法创建本机临时目录。'

cleanup() {
    # Only this mktemp instance and fixed filenames belong to the launcher.
    case ${stage_directory-} in
        "$temp_parent"/remotebridge-usb.??????????) ;;
        *) return ;;
    esac
    [ -d "$stage_directory" ] && [ ! -L "$stage_directory" ] || return
    if [ -d "$stage_directory/logs" ] && [ ! -L "$stage_directory/logs" ]; then
        case ${HOME-} in
            /*)
                if [ "$platform_os" = darwin ]; then
                    saved_log_directory=$HOME/Library/Logs/RemoteBridge
                else
                    saved_log_directory=${XDG_CACHE_HOME:-$HOME/.cache}/RemoteBridge/logs
                fi
                for log_name in bridge-target.jsonl bridge-target.jsonl.1; do
                    if [ -f "$stage_directory/logs/$log_name" ] && [ ! -L "$stage_directory/logs/$log_name" ]; then
                        saved_log=$saved_log_directory/${stage_directory##*/}-$log_name
                        if mkdir -p "$saved_log_directory" && cp "$stage_directory/logs/$log_name" "$saved_log"; then
                            chmod 600 "$saved_log" || true
                            rm -f "$stage_directory/logs/$log_name"
                            printf '启动诊断已保留：%s\n' "$saved_log" >&2
                        else
                            printf '启动诊断仍保留在：%s/logs/%s\n' "$stage_directory" "$log_name" >&2
                        fi
                    fi
                done
                ;;
            *) printf '启动诊断如有生成，将保留在：%s/logs\n' "$stage_directory" >&2 ;;
        esac
        rmdir "$stage_directory/logs" 2>/dev/null || true
    fi
    rm -f "$stage_directory/bridge-target" "$stage_directory/bridge-cli"
    rmdir "$stage_directory" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 129' HUP
trap 'exit 143' TERM

[ -f "$package_directory/SHA256SUMS" ] || fail '缺少 SHA256SUMS；请保留完整 Unix 发布目录。'
expected_hash() {
    awk -v wanted="$platform/$1" '
        $2 == wanted {
            count++
            if (NF == 2 && length($1) == 64 && $1 !~ /[^0123456789abcdefABCDEF]/) {
                digest = tolower($1)
                valid++
            }
        }
        END {
            if (count != 1 || valid != 1) exit 1
            print digest
        }
    ' "$package_directory/SHA256SUMS"
}
for program in bridge-target bridge-cli; do
    expected=$(expected_hash "$program") || fail "$platform/$program 的摘要缺失、重复或格式错误。"
    source_binary=$package_directory/$platform/$program
    [ -f "$source_binary" ] && [ ! -L "$source_binary" ] || fail "缺少有效的平台程序：$source_binary"
    cp "$source_binary" "$stage_directory/$program" || fail "无法复制 $program 到本机临时目录。"
    if [ "$platform_os" = darwin ]; then
        actual=$(shasum -a 256 "$stage_directory/$program") || fail '无法计算 SHA-256；需要系统 shasum。'
    else
        actual=$(sha256sum "$stage_directory/$program") || fail '无法计算 SHA-256；需要系统 sha256sum。'
    fi
    actual=${actual%% *}
    [ "$actual" = "$expected" ] || fail "$program 摘要不一致；请重新复制可信发布包。"
    chmod 700 "$stage_directory/$program" || fail "无法设置 $program 的执行权限。"
done

printf 'Remote Bridge：%s，已复制并校验本机临时程序。\n' "$platform"
if ! "$stage_directory/bridge-target" --version; then
    fail '本机临时目录无法运行程序。请保留系统错误；noexec 可改用本机允许执行的 REMOTE_BRIDGE_TMPDIR，macOS 安全提示须按系统正常流程确认。'
fi
program=bridge-target
if [ "${1-}" = '--cli' ]; then
    program=bridge-cli
    shift
fi
if [ "$program" = bridge-target ]; then
    if [ "$#" -eq 0 ]; then
        set -- ssh --start
    elif [ "$1" = ssh ]; then
        shift
        set -- ssh --start "$@"
    fi
fi
if "$stage_directory/$program" "$@"; then
    program_status=0
else
    program_status=$?
    printf '程序已退出（%s）。请保留上方错误和诊断路径。\n' "$program_status" >&2
fi
exit "$program_status"
