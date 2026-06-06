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

/*  internal dependencies  */
import { classifyBash }    from "./bash-authorize-api.js"
import type { Verdict }    from "./bash-authorize-api.js"

/*  internal package meta-information  */
const pkg = JSON.parse(readFileSync(
    fileURLToPath(new URL("../package.json", import.meta.url)), "utf8")) as
    { name: string, version: string }

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
    .addHelpText("after",
        "\n" +
        "Verdicts:\n" +
        "  allow        the command is genuinely inert         -> auto-approve, no prompt\n" +
        "  ask          the command is known-dangerous         -> force a user prompt\n" +
        "  deny         the command is catastrophic            -> block outright\n" +
        "  passthrough  nothing matched / classification gated -> defer to normal flow\n" +
        "\n" +
        "Example (register as a Claude Code PreToolUse hook in settings.json):\n" +
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
    command?: string
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

/*  main entry point: either classify a command supplied via "--command",
    or read and dispatch a Claude Code "PreToolUse" hook event from stdin  */
async function main (): Promise<void> {
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
