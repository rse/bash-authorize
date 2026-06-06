#!/usr/bin/env node
/*!
**  bash-authorize -- Claude Code "PreToolUse" hook for authorizing Bash commands
**  Copyright (c) 2026 Dr. Ralf S. Engelschall <rse@engelschall.com>
**  Distributed under MIT license <https://spdx.org/licenses/MIT.html>
*/

/*  built-in dependencies  */
import process             from "node:process"
import { readFileSync }    from "node:fs"
import { fileURLToPath }   from "node:url"

/*  external dependencies  */
import { Command, Option } from "commander"
import { execa }           from "execa"

/*  internal dependencies  */
import { classifyBash }    from "./bash-authorize-api.js"
import type { Verdict }    from "./bash-authorize-api.js"

/*  internal package meta-information  */
const pkg = JSON.parse(readFileSync(
    fileURLToPath(new URL("../package.json", import.meta.url)), "utf8")) as
    { name: string, version: string }

/*  the absolute path of this plugin's root directory (the package root,
    one level above the "dist" directory holding this compiled CLI), used
    as the local marketplace source registered with Claude Code  */
const pluginRoot = fileURLToPath(new URL("..", import.meta.url)).replace(/\/$/, "")

/*  the shape of the JSON event Claude Code writes to a hook's stdin
    (only the fields this hook actually consumes are typed explicitly)  */
interface HookEvent {
    hook_event_name?: string
    tool_name?:       string
    tool_input?:      { command?: string }
}

/*  emit a fatal error and terminate the process. A hook crash must never
    block the host agent, so this exits non-zero in a "non-blocking error"
    fashion (anything other than 2), letting the normal flow proceed.  */
const fatal = (msg: string): never => {
    process.stderr.write(`${pkg.name}: ERROR: ${msg}\n`)
    process.exit(1)
}

/*  read the entire stdin stream into a single UTF-8 string  */
const readStdin = async (): Promise<string> => {
    const chunks: Buffer[] = []
    for await (const chunk of process.stdin)
        chunks.push(chunk as Buffer)
    return Buffer.concat(chunks).toString("utf8")
}

/*  map a classifier verdict onto the host agent's "permissionDecision":
    "allow"/"ask"/"deny" are emitted verbatim, while "passthrough" stays
    silent (returns undefined) so the host's normal permission flow runs  */
const permissionDecisionOf = (verdict: Verdict): "allow" | "ask" | "deny" | undefined => {
    switch (verdict) {
        case "allow": return "allow"
        case "ask":   return "ask"
        case "deny":  return "deny"
        default:      return undefined
    }
}

/*  parse the command-line options (flags take precedence over environment variables)  */
const program = new Command()
program
    .name(pkg.name)
    .description("Claude Code \"PreToolUse\" hook for authorizing Bash commands")
    .version(`${pkg.name} ${pkg.version}`, "-V, --version", "show program version information")
    .helpOption("-h, --help", "show this usage help")
    .addOption(new Option("-c, --command <command>", "classify this Bash command directly (instead of reading a hook event from stdin)"))
    .addOption(new Option("-i, --install", "install this tool as a Claude Code plugin (into the chosen settings scope)"))
    .addOption(new Option("-u, --uninstall", "uninstall this tool as a Claude Code plugin (from the chosen settings scope)"))
    .addOption(new Option("-s, --scope <scope>", "settings scope to install into / uninstall from")
        .choices([ "user", "project", "local" ]).default("user"))
    .addHelpText("after",
        "\n" +
        "Verdicts:\n" +
        "  allow        the command is genuinely inert         -> auto-approve, no prompt\n" +
        "  ask          the command is known-dangerous         -> force a user prompt\n" +
        "  deny         the command is catastrophic            -> block outright\n" +
        "  passthrough  nothing matched / classification gated -> defer to normal flow\n" +
        "\n" +
        "Settings scopes (for --install/--uninstall):\n" +
        "  user         ~/.claude/settings.json                -> all projects of the user\n" +
        "  project      ./.claude/settings.json                -> shared with the team (committed)\n" +
        "  local        ./.claude/settings.local.json          -> only the local checkout (ignored)\n" +
        "\n" +
        "Example (install as a Claude Code plugin for the current user):\n" +
        `  $ ${pkg.name} --install\n` +
        "\n" +
        "Example (uninstall the plugin again):\n" +
        `  $ ${pkg.name} --uninstall\n` +
        "\n" +
        "Example (register manually as a Claude Code PreToolUse hook in settings.json):\n" +
        "  {\n" +
        "    \"hooks\": {\n" +
        "      \"PreToolUse\": [ {\n" +
        "        \"matcher\": \"Bash\",\n" +
        "        \"hooks\": [ { \"type\": \"command\", \"command\": \"" + pkg.name + "\" } ]\n" +
        "      } ]\n" +
        "    }\n" +
        "  }\n" +
        "\n" +
        "Example (classify a command directly from the shell):\n" +
        `  $ ${pkg.name} --command "rm -rf /"\n`
    )
    .allowExcessArguments(false)
    .parse()

const opts = program.opts<{
    command?:   string
    install?:   boolean
    uninstall?: boolean
    scope:      "user" | "project" | "local"
}>()

/*  classify a command string and emit the host-agent "hookSpecificOutput"
    JSON for an active verdict, or stay silent (deferring to the normal
    permission flow) for "passthrough", always exiting 0 so a "deny" is
    carried by the JSON, not by the exit code  */
const decide = (command: string): never => {
    const decision = classifyBash(command)

    const permissionDecision = permissionDecisionOf(decision.verdict)
    if (permissionDecision !== undefined) {
        const reason = decision.reason ?? `command classified as "${decision.verdict}" by ${pkg.name}`
        process.stdout.write(JSON.stringify({
            hookSpecificOutput: {
                hookEventName:            "PreToolUse",
                permissionDecision,
                permissionDecisionReason: reason
            }
        }) + "\n")
    }
    /*  "passthrough": stay silent so the host's normal permission flow runs  */

    process.exit(0)
}

/*  classify a command string supplied via "--command" and emit the resulting
    decision as a human-readable "Label: Value" list (verdict and reason) on
    stdout, then exit 0  */
const report = (command: string): never => {
    const decision = classifyBash(command)
    const reason = decision.reason ?? "nothing matched / classification gated"
    process.stdout.write(`Verdict: ${decision.verdict}\n`)
    process.stdout.write(`Reason:  ${reason}\n`)
    process.exit(0)
}

/*  the marketplace and plugin names this tool registers under; Claude Code
    addresses an enabled plugin as "<plugin>@<marketplace>", so both halves
    have to agree with the names declared in the shipped manifest files
    (.claude-plugin/marketplace.json and .claude-plugin/plugin.json)  */
const marketplaceName = pkg.name
const pluginName      = pkg.name
const pluginRef       = `${pluginName}@${marketplaceName}`

/*  run a "claude" CLI sub-process, streaming its output through to our own
    stdout/stderr so the user sees the native progress, and turning a missing
    "claude" binary or a non-zero exit into a fatal error for our caller  */
const claude = async (args: string[]): Promise<void> => {
    process.stdout.write(`${pkg.name}: $ claude ${args.join(" ")}\n`)
    try {
        await execa("claude", args, { stdio: "inherit" })
    }
    catch (err: unknown) {
        const e = err as { code?: string, exitCode?: number }
        if (e.code === "ENOENT")
            fatal("the \"claude\" CLI was not found in $PATH -- install Claude Code first")
        const code = typeof e.exitCode === "number" ? e.exitCode : -1
        fatal(`"claude ${args.join(" ")}" failed (exit code: ${code})`)
    }
}

/*  install this tool as a Claude Code plugin by registering this package's
    root directory as a local marketplace and installing the plugin from it,
    both via the native "claude plugin" sub-commands, then exit 0  */
const install = async (scope: "user" | "project" | "local"): Promise<never> => {
    await claude([ "plugin", "marketplace", "add", pluginRoot, "--scope", scope ])
    await claude([ "plugin", "install", pluginRef, "--scope", scope ])
    process.stdout.write(`${pkg.name}: installed plugin "${pluginRef}" (scope "${scope}")\n`)
    process.exit(0)
}

/*  uninstall this tool as a Claude Code plugin by removing the plugin and
    then dropping the local marketplace registration again, both via the
    native "claude plugin" sub-commands, then exit 0  */
const uninstall = async (scope: "user" | "project" | "local"): Promise<never> => {
    await claude([ "plugin", "uninstall", pluginRef, "--scope", scope ])
    await claude([ "plugin", "marketplace", "remove", marketplaceName, "--scope", scope ])
    process.stdout.write(`${pkg.name}: uninstalled plugin "${pluginRef}" (scope "${scope}")\n`)
    process.exit(0)
}

/*  main entry point: either classify a command supplied via "--command",
    or read and dispatch a Claude Code "PreToolUse" hook event from stdin  */
async function main (): Promise<void> {
    /*  install/uninstall mode: register or unregister this tool as a
        Claude Code plugin via the native "claude plugin" sub-commands  */
    if (opts.install && opts.uninstall)
        fatal("the --install and --uninstall options are mutually exclusive")
    if (opts.install)
        await install(opts.scope)
    if (opts.uninstall)
        await uninstall(opts.scope)

    /*  direct mode: classify the command given on the command line and emit
        a human-readable "Label: Value" list  */
    if (opts.command !== undefined)
        report(opts.command)

    /*  hook mode: read the JSON event from stdin  */
    const input = await readStdin()

    /*  an empty stdin is not a hook invocation -> stay silent and defer  */
    if (input.trim() === "")
        process.exit(0)

    let event: HookEvent
    try {
        event = JSON.parse(input) as HookEvent
    }
    catch (_e) {
        /*  malformed event -> fail safe by deferring to the normal flow  */
        process.exit(0)
    }

    /*  only Bash tool calls carry a command to classify; any other tool
        (or a missing command) is not ours to judge -> defer silently  */
    if (event.tool_name !== "Bash"
        || event.tool_input === undefined
        || typeof event.tool_input.command !== "string")
        process.exit(0)

    decide(event.tool_input.command)
}
main().catch((error) => {
    const msg = error instanceof Error ? error.message : String(error)
    fatal(msg)
})
