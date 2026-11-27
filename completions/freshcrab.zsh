#compdef freshcrab

autoload -U is-at-least

_freshcrab() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'--config=[path to config.yaml]:path:_default' \
'*--packages=[check only these packages (overrides the config list). Repeated use accumulates]:pkg:_default' \
'--queue=[path to the queue state file]:path:_default' \
'(--live)--dry-run[force dry-run mode (default)]' \
'(--dry-run)--live[force live mode (writes the queue; overrides config and env)]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'-V[Print version]' \
'--version[Print version]' \
&& ret=0
}

(( $+functions[_freshcrab_commands] )) ||
_freshcrab_commands() {
    local commands; commands=()
    _describe -t commands 'freshcrab commands' commands "$@"
}

if [ "$funcstack[1]" = "_freshcrab" ]; then
    _freshcrab "$@"
else
    compdef _freshcrab freshcrab
fi
