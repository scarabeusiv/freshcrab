complete -c freshcrab -l config -d 'path to config.yaml' -r
complete -c freshcrab -l packages -d 'check only these packages (overrides the config list)' -r
complete -c freshcrab -l queue -d 'path to the queue state file' -r
complete -c freshcrab -l dry-run -d 'force dry-run mode (default)'
complete -c freshcrab -l live -d 'force live mode (writes the queue; overrides config and env)'
complete -c freshcrab -s h -l help -d 'Print help (see more with \'--help\')'
complete -c freshcrab -s V -l version -d 'Print version'
