# fish completion for nabd

set -l commands check why changes snapshot diff checks version help
set -l checks disk memory cpu services kernel time reboot packages network ports ssh certs procs accounts

complete -c nabd -f
complete -c nabd -n "not __fish_seen_subcommand_from $commands" -a check -d 'Check the machine (default)'
complete -c nabd -n "not __fish_seen_subcommand_from $commands" -a why -d 'Explain one problem in depth'
complete -c nabd -n "not __fish_seen_subcommand_from $commands" -a changes -d 'What changed'
complete -c nabd -n "not __fish_seen_subcommand_from $commands" -a snapshot -d 'Save the security state'
complete -c nabd -n "not __fish_seen_subcommand_from $commands" -a diff -d 'Compare two states'
complete -c nabd -n "not __fish_seen_subcommand_from $commands" -a checks -d 'List the checks'
complete -c nabd -n "not __fish_seen_subcommand_from $commands" -a version -d 'Print the version'
complete -c nabd -n "not __fish_seen_subcommand_from $commands" -a help -d 'Show help'

set -l topics disk slow memory service port dns boot
complete -c nabd -n "__fish_seen_subcommand_from why; and not __fish_seen_subcommand_from $topics" -a disk -d 'What fills a file system'
complete -c nabd -n "__fish_seen_subcommand_from why; and not __fish_seen_subcommand_from $topics" -a slow -d 'What slows the machine now'
complete -c nabd -n "__fish_seen_subcommand_from why; and not __fish_seen_subcommand_from $topics" -a memory -d 'Who uses the memory'
complete -c nabd -n "__fish_seen_subcommand_from why; and not __fish_seen_subcommand_from $topics" -a service -d 'Why a service stopped'
complete -c nabd -n "__fish_seen_subcommand_from why; and not __fish_seen_subcommand_from $topics" -a port -d 'Who listens on a port'
complete -c nabd -n "__fish_seen_subcommand_from why; and not __fish_seen_subcommand_from $topics" -a dns -d 'Why names do not resolve'
complete -c nabd -n "__fish_seen_subcommand_from why; and not __fish_seen_subcommand_from $topics" -a boot -d 'How the last boot went'
complete -c nabd -n "__fish_seen_subcommand_from why; and __fish_seen_subcommand_from disk" -F -a "(__fish_complete_directories)"
complete -c nabd -n "__fish_seen_subcommand_from why; and __fish_seen_subcommand_from service" \
    -a "(systemctl list-units --type=service --all --no-legend --plain --no-pager 2>/dev/null | string replace -r '\.service\s.*' '')"
complete -c nabd -n "__fish_seen_subcommand_from diff" -a "last prev first now"

complete -c nabd -l json -d 'JSON output'
complete -c nabd -l md -d 'Markdown output'
complete -c nabd -l nagios -d 'Nagios plugin output'
complete -c nabd -l prometheus -d 'Prometheus metrics'
complete -c nabd -s o -l output -r -F -d 'Write to a file'
complete -c nabd -s v -l verbose -d 'Show the checks that are OK'
complete -c nabd -s q -l quiet -d 'Only problems'
complete -c nabd -l color -x -a 'auto always never' -d 'When to use colours'
complete -c nabd -l no-color -d 'No colours'
complete -c nabd -l ascii -d 'Plain ASCII symbols'
complete -c nabd -l only -x -a "(__fish_append , $checks)" -d 'Run only these checks'
complete -c nabd -l skip -x -a "(__fish_append , $checks)" -d 'Skip these checks'
complete -c nabd -l timeout -x -d 'Time limit per check (e.g. 30s)'
complete -c nabd -l since -x -a '1h 24h 3d 1w today yesterday boot' -d 'Since when'
complete -c nabd -l keep -x -d 'Keep the newest N snapshots'
complete -c nabd -l list -d 'List the snapshots'
complete -c nabd -l dir -x -a "(__fish_complete_directories)" -d 'Snapshot folder'
complete -c nabd -s h -l help -d 'Help'
complete -c nabd -l version -d 'Print the version'
