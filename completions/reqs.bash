_reqs() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # The basic options for reqs
    opts="-c --connections -d --duration -n --requests -t --threads --timeout -H --header -X --method -s --status-codes --percentiles --no-keepalive -p --pipeline --insecure"

    case "${prev}" in
        -c|--connections|-n|--requests|-t|--threads|--timeout|-p|--pipeline)
            # These expect a number
            return 0
            ;;
        -d|--duration)
            # This expects a duration like 10s, 1m
            return 0
            ;;
        -X|--method)
            COMPREPLY=( $(compgen -W "GET POST PUT DELETE HEAD PATCH OPTIONS" -- "${cur}") )
            return 0
            ;;
        -H|--header)
            # This expects a header string
            return 0
            ;;
        *)
            ;;
    esac

    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
        return 0
    fi
}
complete -F _reqs reqs
