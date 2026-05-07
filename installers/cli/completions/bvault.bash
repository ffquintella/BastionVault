# bash completion stub for bvault.
#
# Phase 1 ships a minimal completion that knows the top-level
# subcommands. A follow-up will replace this with a clap_complete-
# generated artefact emitted at build time.

_bvault() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    if [ "${COMP_CWORD}" -eq 1 ]; then
        local cmds="server operator status read write list delete login version help"
        COMPREPLY=( $(compgen -W "${cmds}" -- "${cur}") )
        return 0
    fi
    case "${prev}" in
        operator)
            COMPREPLY=( $(compgen -W "init unseal seal rotate" -- "${cur}") )
            return 0
            ;;
    esac
    COMPREPLY=()
    return 0
}
complete -F _bvault bvault
