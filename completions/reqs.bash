_reqs() {
    local cur prev words cword
    _init_completion || return

    # All long options
    local long_opts=(
        --connections
        --duration
        --requests
        --threads
        --timeout
        --header
        --method
        --status-codes
        --percentiles
        --no-keepalive
        --pipeline
        --insecure
        --no-color
        --batch
        --help
        --version
    )

    # All short options
    local short_opts="-c -d -n -t -H -X -s -p -h -V"

    case "${prev}" in
        -c|--connections|-n|--requests|-t|--threads|--timeout|-p|--pipeline)
            # Numeric argument — offer a few useful examples
            COMPREPLY=( $(compgen -W "1 2 4 8 10 16 50 100 200 500 1000" -- "${cur}") )
            return 0
            ;;
        -d|--duration)
            # Duration strings
            COMPREPLY=( $(compgen -W "1s 5s 10s 30s 1m 2m 5m 10m 1m30s" -- "${cur}") )
            return 0
            ;;
        -X|--method)
            COMPREPLY=( $(compgen -W "GET POST PUT DELETE PATCH HEAD OPTIONS TRACE" -- "${cur}") )
            return 0
            ;;
        -H|--header)
            # Common headers to suggest
            COMPREPLY=( $(compgen -W \
                "Accept:application/json \
                 Accept:text/html \
                 Authorization:Bearer \
                 Content-Type:application/json \
                 Content-Type:application/x-www-form-urlencoded \
                 User-Agent:reqs" -- "${cur}") )
            return 0
            ;;
        --percentiles)
            COMPREPLY=( $(compgen -W \
                "50,90,99 50,75,90,95,99 50,75,90,95,99,99.9 99 99.9 99.99" -- "${cur}") )
            return 0
            ;;
    esac

    # Complete flags
    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "${long_opts[*]} ${short_opts}" -- "${cur}") )
        return 0
    fi

    # If no URL has been provided yet, suggest http/https prefixes
    local has_url=0
    for word in "${words[@]:1:${#words[@]}-2}"; do
        if [[ "${word}" == http://* || "${word}" == https://* ]]; then
            has_url=1
            break
        fi
    done

    if [[ ${has_url} -eq 0 ]]; then
        COMPREPLY=( $(compgen -W "http:// https://" -- "${cur}") )
    fi
}

complete -F _reqs reqs
