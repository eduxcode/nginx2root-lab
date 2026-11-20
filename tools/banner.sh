#!/usr/bin/env bash
# Colored ASCII banner for the nginx2root lab.
# Uso: ./tools/banner.sh [--plain]
set -u

sub="CVE-2026-123007  ·  HTTP/2 flow-control underflow  ·  lab by eduxcode"
width=67

plain=0
[ "${1:-}" = "--plain" ] && plain=1
[ -n "${NO_COLOR:-}" ] && plain=1

art=(
' _   _  _____ _____ _   ___   _____  _____   ____   ____ _______'
'| \ | |/ ____|_   _| \ | \ \ / /__ \|  __ \ / __ \ / __ \__   __|'
'|  \| | |  __  | | |  \| |\ V /   ) | |__) | |  | | |  | | | |'
'| . ` | | |_ | | | | . ` | > <   / /|  _  /| |  | | |  | | | |'
'| |\  | |__| |_| |_| |\  |/ . \ / /_| | \ \| |__| | |__| | | |'
'|_| \_|\_____|_____|_| \_/_/ \_\____|_|  \_\\____/ \____/  |_|'
)

colors=(196 202 208 214 220 226)

if [ "$plain" -eq 1 ]; then
    for line in "${art[@]}"; do
        printf '%s\n' "$line"
    done
    printf '%s\n' "$(printf '%.0s─' $(seq 1 $width))"
    pad=$(( (width - ${#sub}) / 2 ))
    printf '%*s%s\n' "$pad" "" "$sub"
    printf '%s\n' "$(printf '%.0s─' $(seq 1 $width))"
else
    i=0
    for line in "${art[@]}"; do
        printf '\033[38;5;%sm%s\033[0m\n' "${colors[$i]}" "$line"
        i=$((i + 1))
    done
    printf '\033[38;5;245m%s\033[0m\n' "$(printf '%.0s─' $(seq 1 $width))"
    pad=$(( (width - ${#sub}) / 2 ))
    printf '\033[38;5;250m%*s%s\033[0m\n' "$pad" "" "$sub"
    printf '\033[38;5;245m%s\033[0m\n' "$(printf '%.0s─' $(seq 1 $width))"
fi
