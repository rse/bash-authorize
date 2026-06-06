
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
  (e.g. `ls`, `cat`, `grep`, `git status`).

- **ask** &mdash; the command is *known-dangerous* but legitimate, so a
  user confirmation *prompt is forced* (e.g. `rm -rf`, `git push`,
  `chmod`, `curl`).

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

Installation
------------

```
$ npm install -g bash-authorize
```

Usage
-----

```
Usage: bash-authorize [options]

Claude Code "PreToolUse" hook for authorizing Bash commands

Options:
  -V, --version            show program version information
  -c, --command <command>  classify this Bash command directly (instead of
                           reading a hook event from stdin)
  -h, --help               show this usage help

Verdicts:
  allow        the command is genuinely inert       -> auto-approve, no prompt
  ask          the command is known-dangerous       -> force a user prompt
  deny         the command is catastrophic          -> block outright
  passthrough  nothing matched / classification gated -> defer to normal flow

Example (register as a Claude Code PreToolUse hook in settings.json):
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
hook protocol and classifies a command string directly (still emitting
the same JSON, or nothing for `passthrough`). Combine it with
`--verbose` to see the resolved verdict and reason on `stderr`.

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

