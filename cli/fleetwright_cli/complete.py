"""Shell completion for fw, generated from its own argument parser, so it can't fall out
of step with the commands."""

from __future__ import annotations

import argparse


def tree(parser: argparse.ArgumentParser, path: tuple = ()) -> dict:
    """{command path: (subcommands, options, choices for options)}"""
    out = {}
    subs, opts, choices = [], [], {}
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            for name, p in a.choices.items():
                subs.append((name, next((c.help or "" for c in a._choices_actions if c.dest == name), "")))
                out.update(tree(p, path + (name,)))
        elif a.option_strings:
            opts += [o for o in a.option_strings if o.startswith("--")]
            if a.choices:
                for o in a.option_strings:
                    choices[o] = list(a.choices)
    out[path] = (subs, opts, choices)
    return out


def bash(parser) -> str:
    t = tree(parser)
    cases = []
    for path, (subs, opts, choices) in t.items():
        words = " ".join([s for s, _ in subs] + opts)
        choice_cases = "".join(f"            {o}) COMPREPLY=($(compgen -W '{' '.join(c)}' -- \"$cur\")); return;;\n"
                               for o, c in choices.items())
        cases.append(f"        '{' '.join(path)}')\n            case \"$prev\" in\n{choice_cases}"
                     f"            esac\n            COMPREPLY=($(compgen -W '{words}' -- \"$cur\"));;")
    return f"""# fw completion for bash: eval "$(fw completion bash)"
_fw() {{
    local cur=${{COMP_WORDS[COMP_CWORD]}} prev=${{COMP_WORDS[COMP_CWORD-1]}} path="" w i
    for ((i = 1; i < COMP_CWORD; i++)); do
        w=${{COMP_WORDS[i]}}
        case "$w" in -*) continue;; esac
        case " $(_fw_subs "$path") " in *" $w "*) path="${{path:+$path }}$w";; esac
    done
    case "$path" in
{chr(10).join(cases)}
    esac
}}
_fw_subs() {{
    case "$1" in
{chr(10).join(f"        '{' '.join(p)}') echo '{' '.join(s for s, _ in subs)}';;" for p, (subs, _, _) in t.items())}
    esac
}}
complete -F _fw fw
"""


def zsh(parser) -> str:
    return ("# fw completion for zsh: eval \"$(fw completion zsh)\"\n"
            "autoload -U +X bashcompinit && bashcompinit\n" + bash(parser))


def fish(parser) -> str:
    t = tree(parser)
    lines = ["# fw completion for fish: fw completion fish > ~/.config/fish/completions/fw.fish", "complete -c fw -f"]
    for path, (subs, opts, choices) in t.items():
        if not path:
            cond = "__fish_use_subcommand"
        else:
            cond = (f"__fish_seen_subcommand_from {path[-1]}" if len(path) == 1 else
                    f"__fish_seen_subcommand_from {path[0]}; and __fish_seen_subcommand_from {path[-1]}")
            if subs:
                cond += f"; and not __fish_seen_subcommand_from {' '.join(s for s, _ in subs)}"
        for name, help_text in subs:
            lines.append(f"complete -c fw -n '{cond}' -a {name} -d {help_text!r}")
        for o in opts:
            extra = f" -xa '{' '.join(choices[o])}'" if o in choices else ""
            lines.append(f"complete -c fw -n '{cond}' -l {o[2:]}{extra}")
    return "\n".join(lines) + "\n"


def script(parser, shell: str) -> str:
    return {"bash": bash, "zsh": zsh, "fish": fish}[shell](parser)
