
Bash-Authorize
==============

**Claude Code "PreToolUse" hook for authorizing Bash commands**

<p/>
<img src="https://nodei.co/npm/bash-authorize.png?downloads=true&stars=true" alt=""/>

<p/>

[![github (author stars)](https://img.shields.io/github/stars/rse?logo=github&label=author%20stars&color=%233377aa)](https://github.com/rse)
[![github (author followers)](https://img.shields.io/github/followers/rse?label=author%20followers&logo=github&color=%234477aa)](https://github.com/rse)

Abstract
--------

This is a small Command-Line Interface (CLI) acting as a *Claude Code*
`PreToolUse` hook for the `Bash` tool. It parses the to-be-executed
Bash command into an Abstract Syntax Tree (with the help of the
[`unbash`](https://npmjs.com/unbash) parser), recursively walks the
full command structure, and classifies it into one of four verdicts:

- **allow** &mdash; the command is *genuinely inert* (read-only, no
  side-effects), so it is *auto-approved* without prompting the user
  (e.g. `ls`, `cat`, `grep`, `git status`, or `curl`/`wget` as long
  as they stream to stdout and do not write any file).

- **ask** &mdash; the command is *known-dangerous* but legitimate, so a
  user confirmation *prompt is forced* (e.g. `rm -rf`, `git push`,
  `chmod`).

- **deny** &mdash; the command is *catastrophic* and near-never
  legitimate, so it is *blocked outright* (e.g. `rm -rf /`, `mkfs.*`,
  `dd of=/dev/...`).

- **passthrough** &mdash; nothing matched, or the classification was
  *gated* by a hard safety condition (a mutating redirect, a background
  job, an embedded `$(...)` substitution, a non-literal command name,
  etc.), so the hook *stays silent* and defers to *Claude Code*'s normal
  permission flow.

The classification is *fail-safe* throughout: any parse error, thrown
exception, or unexpected/unmatched construct yields `passthrough`, so
the tool never crashes the host agent and never auto-approves on doubt.

> [!CAUTION]
> THIS IS A SECURITY-RELEVANT AND RISKY PIECE OF SOFTWARE. IT IS
> PROVIDED AS-IS, JUST FOR YOUR CONVENIENCE, AND WITHOUT ANY GUARANTEE
> THAT IT WORKS CORRECTLY AT ALL. USE IT ENTIRELY AT YOUR OWN RISK!

Installation
------------

Install the CLI globally:

```
$ npm install -g bash-authorize
```

Then register it as a *Claude Code* plugin (this is the recommended way to
hook it into *Claude Code* -- it drives the native `claude plugin` commands
under the hood, so no manual `settings.json` editing is needed):

```
$ bash-authorize --install
```

To remove the plugin again:

```
$ bash-authorize --uninstall
```

Both honor a `--scope user|project|local` flag (defaulting to `user`),
matching the installation scopes of *Claude Code*'s own `claude plugin`
sub-commands.

Usage
-----

```
Usage: bash-authorize [options]

Claude Code "PreToolUse" hook for authorizing Bash commands

Options:
  -V, --version            show program version information
  -c, --command <command>  classify this Bash command directly (instead of
                           reading a hook event from stdin)
  -i, --install            install this tool as a Claude Code plugin (into the
                           chosen settings scope)
  -u, --uninstall          uninstall this tool as a Claude Code plugin (from the
                           chosen settings scope)
  -s, --scope <scope>      settings scope to install into / uninstall from
                           (choices: "user", "project", "local", default: "user")
  -h, --help               show this usage help

Verdicts:
  allow        the command is genuinely inert         -> auto-approve, no prompt
  ask          the command is known-dangerous         -> force a user prompt
  deny         the command is catastrophic            -> block outright
  passthrough  nothing matched / classification gated -> defer to normal flow

Settings scopes (for --install/--uninstall):
  user         ~/.claude/settings.json                -> all projects of the user
  project      ./.claude/settings.json                -> shared with the team (committed)
  local        ./.claude/settings.local.json          -> only the local checkout (ignored)

Example (install as a Claude Code plugin for the current user):
  $ bash-authorize --install

Example (uninstall the plugin again):
  $ bash-authorize --uninstall

Example (register manually as a Claude Code PreToolUse hook in settings.json):
  {
    "hooks": {
      "PreToolUse": [ {
        "matcher": "Bash",
        "hooks": [ { "type": "command", "command": "bash-authorize" } ]
      } ]
    }
  }

Example (classify a command directly from the shell):
  $ bash-authorize --command "rm -rf /"
```

Claude Code Plugin
------------------

Besides being a standalone CLI, this package *is* a self-contained *Claude
Code* plugin. Its plugin manifest lives under `.claude-plugin/` and a
conventional `hooks/hooks.json` wires the bundled CLI into the `PreToolUse`
event for the `Bash` tool:

```
.claude-plugin/marketplace.json   local-directory marketplace descriptor
.claude-plugin/plugin.json        plugin manifest (name, version, author, ...)
hooks/hooks.json                  PreToolUse/Bash hook -> bundled CLI
```

The hook invokes the plugin's *own* bundled binary via the
`${CLAUDE_PLUGIN_ROOT}` variable *Claude Code* exposes to plugin hooks, so it
works regardless of whether `bash-authorize` is also on your `$PATH`:

```json
{
    "hooks": {
        "PreToolUse": [ {
            "matcher": "Bash",
            "hooks": [ {
                "type": "command",
                "command": "node \"${CLAUDE_PLUGIN_ROOT}/dist/bash-authorize-cli.js\""
            } ]
        } ]
    }
}
```

Running `bash-authorize --install` registers this package's directory as a
local *Claude Code* plugin marketplace and installs the plugin from it, both
via the native `claude plugin marketplace add` and `claude plugin install`
sub-commands; `--uninstall` reverses both steps again.

How It Works
------------

As a *Claude Code* `PreToolUse` hook, `bash-authorize` is invoked once
per `Bash` tool call. *Claude Code* writes a JSON event to the hook's
`stdin`, containing (among other fields) the tool name and the Bash
command string under `tool_input.command`. The hook classifies that
command and responds via `stdout`:

- For an **allow**/**ask**/**deny** verdict, it writes the modern
  `hookSpecificOutput` permission decision and exits `0`:

  ```json
  {
      "hookSpecificOutput": {
          "hookEventName":            "PreToolUse",
          "permissionDecision":       "deny",
          "permissionDecisionReason": "recursive forced removal of root is catastrophic"
      }
  }
  ```

- For a **passthrough** verdict, it writes *nothing* and exits `0`,
  letting *Claude Code* apply its normal permission flow.

For testing and scripting, the `--command` option bypasses the stdin
hook protocol and classifies a command string directly, printing the
resolved verdict and reason in a human-readable form to `stdout` (for
all verdicts, including `passthrough`).

License
-------

Copyright &copy; 2026 Dr. Ralf S. Engelschall (http://engelschall.com/)

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

