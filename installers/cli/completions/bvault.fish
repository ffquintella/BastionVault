# fish completion stub for bvault. Phase 1 minimal implementation;
# a follow-up will switch to clap_complete-generated output.

complete -c bvault -f

# Top-level subcommands.
complete -c bvault -n '__fish_use_subcommand' -a server   -d 'Run a BastionVault server'
complete -c bvault -n '__fish_use_subcommand' -a operator -d 'Init / unseal / seal / rotate'
complete -c bvault -n '__fish_use_subcommand' -a status   -d 'Show seal and health status'
complete -c bvault -n '__fish_use_subcommand' -a read     -d 'Read a secret'
complete -c bvault -n '__fish_use_subcommand' -a write    -d 'Write a secret'
complete -c bvault -n '__fish_use_subcommand' -a list     -d 'List under a path'
complete -c bvault -n '__fish_use_subcommand' -a delete   -d 'Delete at a path'
complete -c bvault -n '__fish_use_subcommand' -a login    -d 'Authenticate'
complete -c bvault -n '__fish_use_subcommand' -a version  -d 'Print version'
complete -c bvault -n '__fish_use_subcommand' -a help     -d 'Show help'

# operator <subcommand>
complete -c bvault -n '__fish_seen_subcommand_from operator' -a 'init unseal seal rotate'
