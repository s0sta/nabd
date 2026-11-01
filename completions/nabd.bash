# bash completion for nabd                                    -*- shell-script -*-

_nabd() {
    local cur prev cword
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}
    cword=$COMP_CWORD

    local commands="check why changes snapshot diff checks version help"
    local topics="disk slow memory service port dns boot"
    local checks="disk memory cpu services kernel time reboot packages network ports ssh certs procs accounts"
    local options="--json --md --nagios --prometheus --output --verbose --quiet --color --no-color --ascii
        --only --skip --timeout --since --keep --list --dir --help --version"

    case $prev in
        --only|--skip)
            local prefix=""
            [[ $cur == *,* ]] && prefix=${cur%,*},
            COMPREPLY=($(compgen -P "$prefix" -W "$checks" -- "${cur##*,}"))
            compopt -o nospace 2>/dev/null
            return ;;
        --color|--colour)
            COMPREPLY=($(compgen -W "auto always never" -- "$cur")); return ;;
        --since)
            COMPREPLY=($(compgen -W "1h 24h 3d 1w today yesterday boot" -- "$cur")); return ;;
        -o|--output|--dir)
            COMPREPLY=($(compgen -f -- "$cur")); compopt -o filenames 2>/dev/null; return ;;
        --timeout|--keep)
            return ;;
    esac

    if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "$options" -- "$cur"))
        return
    fi

    # the command and its arguments, without options and their values
    local words=() i w
    for ((i = 1; i < cword; i++)); do
        w=${COMP_WORDS[i]}
        case $w in
            --only|--skip|--color|--colour|--since|-o|--output|--dir|--timeout|--keep) ((i++)) ;;
            -*) ;;
            *) words+=("$w") ;;
        esac
    done

    case ${words[0]} in
        "")
            COMPREPLY=($(compgen -W "$commands" -- "$cur")) ;;
        why)
            case ${#words[@]} in
                1) COMPREPLY=($(compgen -W "$topics" -- "$cur")) ;;
                2)
                    case ${words[1]} in
                        disk) COMPREPLY=($(compgen -d -- "$cur")); compopt -o filenames 2>/dev/null ;;
                        service)
                            local units
                            units=$(systemctl list-units --type=service --all --no-legend --plain --no-pager 2>/dev/null |
                                awk '{sub(/\.service$/, "", $1); print $1}')
                            COMPREPLY=($(compgen -W "$units" -- "$cur")) ;;
                    esac ;;
            esac ;;
        diff)
            COMPREPLY=($(compgen -W "last prev first now" -- "$cur")) ;;
        help)
            [[ ${#words[@]} -eq 1 ]] && COMPREPLY=($(compgen -W "$commands" -- "$cur")) ;;
    esac
}

complete -F _nabd nabd
