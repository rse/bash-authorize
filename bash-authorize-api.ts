/*
**  bash-authorize -- Claude Code "PreToolUse" hook for authorizing Bash commands
**  Copyright (c) 2026 Dr. Ralf S. Engelschall <rse@engelschall.com>
**  Distributed under MIT license <https://spdx.org/licenses/MIT.html>
*/

/*  external dependencies  */
import { parse } from "unbash"
import type {
    Node, Statement, CompoundList, Command as BashCommand, Word, WordPart,
    Redirect, AssignmentPrefix, Script, ArithmeticExpression,
    TestExpression
} from "unbash"

/*  the per-command (and aggregate) verdicts  */
export type Verdict = "allow" | "ask" | "deny" | "passthrough"

/*  an "allow" rule matches a genuinely-inert command by its name ("cmd")
    plus, optionally, every listed subcommand positional token ("subcommands",
    so "git status" matches "git status -s" but not "git push"). If any flag
    listed in the optional "denyFlags" set is present, the leaf is downgraded
    from "allow" to "passthrough" (e.g. "find -delete"). If any substring
    listed in the optional "denyArgSubstr" set occurs inside any argument
    token, the leaf is likewise downgraded -- this catches danger carried not
    by a flag but inside a program-text argument (e.g. an awk program
    containing "system(" or a "print >" file redirection). If an optional
    "argGuard" predicate is given, it receives the leaf's literal argument
    vector and must return true for the leaf to stay "allow", else it is
    downgraded -- this is used where simple substring matching is unreliable
    (e.g. a "sed" script whose terse one-letter "w"/"e" commands collide with
    substitution data and whose delimiter is freely chosen), so the guard
    instead owns the command's own argument grammar and allow-lists only a
    verified-safe shape, rejecting everything else.  */
interface AllowRule {
    permission:     "allow"
    cmd:            string
    subcommands?:   string[]
    denyFlags?:     string[]
    denyArgSubstr?: string[]
    argGuard?:      (args: string[]) => boolean
    reason?:        string
}

/*  a "risk" rule matches a known-dangerous command. The command name is
    matched either exactly ("cmd") or by a literal name prefix ("cmdPrefix",
    so "mkfs." matches "mkfs.ext4"/"mkfs.vfat"). Additional optional predicates ALL have to
    hold for the rule to fire: "subcommands" requires every listed literal
    positional token to be present (e.g. "push" for "git push"); "flags"
    requires every listed flag to be present by set-membership over the
    command's parsed flags -- order-independent, bundle-aware (so "-rf"
    matches "-r" and "-f" alike) and long-form-alias-aware (so "--force"
    counts as "-f"); "argTokens" requires every listed token to appear
    verbatim among the arguments (e.g. "/" for "rm -rf /", which keeps
    "rm -rf x" out of the catastrophic set); and "argSubstr" requires every
    listed substring to occur inside some argument token (e.g. "of=/dev/"
    for "dd of=/dev/sda"). An absent predicate is vacuously satisfied, so a
    bare "{ cmd }" matches the command regardless of its arguments.  */
interface RiskRule {
    permission:   "ask" | "deny"
    cmd?:         string
    cmdPrefix?:   string
    subcommands?: string[]
    flags?:       string[]
    aliases?:     Record<string, string[]>
    argTokens?:   string[]
    argSubstr?:   string[]
    reason?:      string
}

/*  the rule for allow or risk  */
type Rule = AllowRule | RiskRule

/*  the default verdict when no rule matches a leaf command  */
const DEFAULT: Verdict = "passthrough"

/*  transparent wrappers whose first non-flag argument is the real command
    to classify (e.g. "env FOO=bar ls" or "xargs rm" resolve to "ls"/"rm")  */
const WRAPPERS = new Set([ "env", "xargs", "nice", "nohup", "command", "builtin" ])

/*  privilege escalators are a hard barrier (not an allow-unwrapper): they
    cap the aggregate verdict at "ask" regardless of the inner command's
    safety, yet the inner command is still traversed so an inner
    catastrophic command can still escalate the verdict to "deny"  */
const PRIVILEGE = new Set([ "sudo", "doas" ])

/*  decide whether a single "sed" script argument is verified-safe, i.e.
    provably free of any file-writing ("w"/"W" command or "s///w" flag),
    file-reading ("r"/"R"), or shell-executing ("e" command or "s///e"
    flag) construct. Substring matching is unreliable here because sed's
    one-letter commands collide with substitution data and the delimiter
    is freely chosen, so this instead allow-lists only a small, common,
    obviously-inert grammar and rejects (-> "passthrough") anything else:
    a ";"/newline-separated sequence of either a substitution
    "s<D>...<D>...<D>[flags]" whose flags are restricted to the inert set
    "g/p/i/I/m/M/N" (notably excluding "e" and "w"), or an
    optionally-addressed plain command drawn from the inert command set
    "p/P/d/D/q/Q/l/n/N/h/H/g/G/x/z/=" (no operand). Addresses are limited
    to line numbers, "$", and "/regex/" forms. Anything richer (a "w"/"r"/
    "e"/"a"/"i"/"c"/"y"/"{ }" block, an unfamiliar flag, a custom label,
    etc.) simply fails the guard and falls back to the host prompt.  */
const SED_ADDR    = "(?:[0-9]+|\\$|/(?:\\\\.|[^/\\\\])*/[IM]?)"
const SED_RANGE   = `(?:${SED_ADDR}(?:,${SED_ADDR})?)?`
const SED_SUBST   = "s([^\\sa-zA-Z0-9\\\\])(?:\\\\.|(?!\\1).)*\\1(?:\\\\.|(?!\\1).)*\\1[gpiImMN0-9]*"
const SED_PLAIN   = "[pPdDqQlnNhHgGxz=]"
const SED_CMD     = new RegExp(`^${SED_RANGE}\\s*(?:${SED_SUBST}|${SED_PLAIN})$`)
const sedScriptText = (text: string): boolean => {
    /*  split one script into its individual commands on ";" and newlines
        (a conservative split: any embedded ";"/newline inside a regex or
        replacement just yields a fragment that fails to match below and
        thus correctly denies auto-approval rather than mis-approving)  */
    const parts = text.split(/[;\n]/).map((p) => p.trim()).filter((p) => p !== "")
    if (parts.length === 0)
        return false
    return parts.every((p) => SED_CMD.test(p))
}

/*  validate a whole "sed" argument vector: locate every script source and
    require each to be verified-safe, while letting flags and trailing file
    operands pass freely. The script comes either from each "-e"/"--expression"
    option (its glued or following value) or, when no "-e" is present, from
    the first non-flag positional token (the remaining positionals are input
    files). A "--" terminator ends option processing. Any "-f"/"--file" is
    already denied upstream via "denyFlags", so a script read from a file
    never reaches this guard.  */
const sedArgsAreSafe = (args: string[]): boolean => {
    const scripts: string[] = []
    let sawExpr = false
    let endOpts = false
    let firstPositional = true
    for (let i = 0; i < args.length; i++) {
        const arg = args[i]
        if (!endOpts && arg === "--") {
            endOpts = true
            continue
        }
        if (!endOpts && (arg === "-e" || arg === "--expression")) {
            /*  the script is the following token (must exist)  */
            if (i + 1 >= args.length)
                return false
            scripts.push(args[++i])
            sawExpr = true
            continue
        }
        if (!endOpts && arg.startsWith("--expression="))  {
            scripts.push(arg.slice("--expression=".length))
            sawExpr = true
            continue
        }
        if (!endOpts && arg.startsWith("-e") && arg.length > 2) {
            /*  glued short form "-eSCRIPT"  */
            scripts.push(arg.slice(2))
            sawExpr = true
            continue
        }
        if (!endOpts && arg.startsWith("-"))
            /*  any other flag (e.g. "-n", "-E", "-r", "-z", "-u") is inert
                here: the mutating ones were denied upstream by "denyFlags"  */
            continue
        /*  a positional: the first is the script when no "-e" was given,
            every other positional is an input file and needs no check  */
        if (!sawExpr && firstPositional)
            scripts.push(arg)
        firstPositional = false
    }
    if (scripts.length === 0)
        return false
    return scripts.every((s) => sedScriptText(s))
}

/*  the ordered rule set: first match wins. "allow" rules enumerate a
    conservative, genuinely-inert command set; "risk" rules enumerate the
    known-dangerous ones (mostly "ask", with only a tiny catastrophic set
    "deny"). Everything else falls through to the "passthrough" default.  */
const RULES: Rule[] = [
    /*  catastrophic, near-never-legitimate operations -> actively deny.
        These come first so first-match-wins beats the broader "ask" rules
        below (e.g. "rm -rf /" denies before the generic "rm -rf" asks).  */
    {   permission: "deny",  cmd: "mkfs",
        reason: "filesystem creation is destructive" },
    {   permission: "deny",  cmdPrefix: "mkfs.",
        reason: "filesystem creation is destructive" },
    {   permission: "deny",  cmd: "dd", argSubstr: [ "of=/dev/" ],
        reason: "raw write to a device is catastrophic" },
    {   permission: "deny",  cmd: "rm", flags: [ "-r", "-f" ],
        aliases: { "-r": [ "--recursive", "-R" ], "-f": [ "--force" ] }, argTokens: [ "/" ],
        reason: "recursive forced removal of root is catastrophic" },

    /*  genuinely-inert, read-only commands -> auto-approve  */
    {   permission: "allow", cmd: "ls",
        reason: "directory listing is read-only" },
    {   permission: "allow", cmd: "pwd",
        reason: "print working directory is read-only" },
    {   permission: "allow", cmd: "echo",
        reason: "echo is inert" },
    {   permission: "allow", cmd: "cat",
        reason: "file read is non-mutating" },
    {   permission: "allow", cmd: "head",
        reason: "file read is non-mutating" },
    {   permission: "allow", cmd: "tail",
        reason: "file read is non-mutating" },
    {   permission: "allow", cmd: "wc",
        reason: "counting is read-only" },
    {   permission: "allow", cmd: "which",
        reason: "executable lookup is read-only" },
    {   permission: "allow", cmd: "grep",
        denyFlags: [ "-o", "--output", "-r", "-R" ],
        reason: "pattern search is read-only" },
    {   permission: "allow", cmd: "find",
        denyFlags: [ "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf" ],
        reason: "filesystem search is read-only" },
    {   permission: "allow", cmd: "awk",
        denyFlags: [ "-i", "--in-place", "-f", "--file" ],
        denyArgSubstr: [
            "system(", "print>", "print >", "printf>", "printf >", "fflush",
            "|getline", "| getline", "getline<", "getline <", ">\"", "> \"", ">>", "|\"", "| \"" ],
        reason: "text processing is read-only" },
    {   permission: "allow", cmd: "sed",
        denyFlags: [ "-i", "--in-place", "-f", "--file" ], argGuard: sedArgsAreSafe,
        reason: "stream editing is read-only when its script writes/executes nothing" },
    {   permission: "allow", cmd: "node", denyFlags: [ "-e", "--eval", "-p", "--print" ],
        reason: "node without an inline eval/print flag is treated as inert" },
    {   permission: "allow", cmd: "git", subcommands: [ "status" ],
        reason: "git status is read-only" },
    {   permission: "allow", cmd: "git", subcommands: [ "log" ],
        reason: "git log is read-only" },
    {   permission: "allow", cmd: "git", subcommands: [ "diff" ],
        reason: "git diff is read-only" },
    {   permission: "allow", cmd: "git", subcommands: [ "branch" ],
        reason: "git branch listing is read-only" },
    {   permission: "allow", cmd: "git", subcommands: [ "show" ],
        reason: "git show is read-only" },

    /*  known-dangerous operations -> actively ask  */
    {   permission: "ask",   cmd: "rm", flags: [ "-r", "-f" ],
        aliases: { "-r": [ "--recursive", "-R" ], "-f": [ "--force" ] },
        reason: "recursive forced removal is destructive" },
    {   permission: "ask",   cmd: "git", subcommands: [ "push" ],
        reason: "git push mutates the remote" },
    {   permission: "ask",   cmd: "chmod",
        reason: "permission change is mutating" },
    {   permission: "ask",   cmd: "chown",
        reason: "ownership change is mutating" },
    {   permission: "ask",   cmd: "kill",
        reason: "signalling processes is impactful" },
    {   permission: "ask",   cmd: "curl",
        reason: "network access is side-effecting" },
    {   permission: "ask",   cmd: "wget",
        reason: "network access is side-effecting" }
]

/*  normalize a leaf command's argument flags into a set of canonical flag
    tokens: split bundled short flags ("-rf" -> "-r","-f"), keep long flags
    ("--force") intact, and fold long-form aliases back onto their canonical
    short flag via the rule's "aliases" map (so "--force" counts as "-f")  */
const flagSet = (args: string[], aliases?: Record<string, string[]>): Set<string> => {
    const set = new Set<string>()
    for (const arg of args) {
        if (arg.startsWith("--"))
            set.add(arg)
        else if (arg.startsWith("-") && arg.length > 1)
            for (const ch of arg.slice(1))
                set.add("-" + ch)
    }
    if (aliases !== undefined)
        for (const canonical of Object.keys(aliases))
            for (const alias of aliases[canonical])
                if (set.has(alias))
                    set.add(canonical)
    return set
}

/*  the result of classifying a single leaf or a whole script: the verdict
    plus the optional human-readable reason of the rule that produced it  */
export interface Decision {
    verdict: Verdict
    reason?: string
}

/*  classify a single resolved leaf command (its name plus literal argument
    tokens) against the ordered rule set, returning the first match's
    decision, or the "passthrough" default when nothing matches  */
const classifyLeaf = (name: string, args: string[]): Decision => {
    for (const rule of RULES) {
        if (rule.permission === "allow") {
            /*  allow rule: the command name plus every listed subcommand
                positional token (order-independent) must hold  */
            if (name !== rule.cmd)
                continue
            if (rule.subcommands !== undefined
                && !rule.subcommands.every((s) => args.includes(s)))
                continue
            if (rule.denyFlags !== undefined) {
                const flags = flagSet(args)
                if (rule.denyFlags.some((f) => flags.has(f) || args.includes(f)))
                    return { verdict: "passthrough" }
            }
            if (rule.denyArgSubstr !== undefined) {
                const denyArgSubstr = rule.denyArgSubstr
                if (args.some((a) => denyArgSubstr.some((s) => a.includes(s))))
                    return { verdict: "passthrough" }
            }
            if (rule.argGuard !== undefined && !rule.argGuard(args))
                return { verdict: "passthrough" }
            return { verdict: "allow", reason: rule.reason }
        }
        else {
            /*  risk rule: the command name plus every present predicate
                ("subcommands"/"flags"/"argTokens"/"argSubstr") must hold  */
            let nameOk = false
            if (rule.cmd !== undefined)
                nameOk = name === rule.cmd
            else if (rule.cmdPrefix !== undefined)
                nameOk = name.startsWith(rule.cmdPrefix)
            if (!nameOk)
                continue
            if (rule.subcommands !== undefined
                && !rule.subcommands.every((s) => args.includes(s)))
                continue
            if (rule.flags !== undefined && rule.flags.length > 0) {
                const flags = flagSet(args, rule.aliases)
                if (!rule.flags.every((f) => flags.has(f)))
                    continue
            }
            if (rule.argTokens !== undefined
                && !rule.argTokens.every((t) => args.includes(t)))
                continue
            if (rule.argSubstr !== undefined
                && !rule.argSubstr.every((s) => args.some((a) => a.includes(s))))
                continue
            return { verdict: rule.permission, reason: rule.reason }
        }
    }
    return { verdict: DEFAULT }
}

/*  combine two verdicts with safety-first precedence
    "deny" > "ask" > "allow" > "passthrough": once any leaf (or hard gate)
    has yielded "deny" the aggregate is "deny", an "ask" wins over a mere
    "allow", and an "allow" only survives when nothing weaker contradicts it  */
const PRECEDENCE: Record<Verdict, number> = {
    "deny":        3,
    "ask":         2,
    "allow":       1,
    "passthrough": 0
}

/*  determine whether a word is a plain literal (no expansion parts such as
    "$(...)", "${...}", or process substitution): only such words may name
    an auto-approvable command and only such suffix tokens are trustworthy  */
const isLiteralWord = (word: Word): boolean => {
    if (word.parts === undefined)
        return true
    return word.parts.every((p) => p.type === "Literal"
        || p.type === "SingleQuoted" || p.type === "DoubleQuoted")
}

/*  whether a word part embeds a nested Script (command/process/arithmetic
    substitution) that must itself be traversed and may not be auto-approved  */
const partHasScript = (part: WordPart): boolean =>
    part.type === "CommandExpansion"
    || part.type === "ProcessSubstitution"
    || part.type === "ArithmeticExpansion"

/*  the inert sink paths a write redirect may target without mutating the
    filesystem (so "cmd >/dev/null" stays as harmless as "cmd" itself)  */
const INERT_SINKS = new Set([ "/dev/null", "/dev/stdout", "/dev/stderr" ])

/*  classify whether a redirect actually mutates the filesystem (and thus
    must trip the hard safety gate) or is benign for an otherwise-inert
    command. Benign cases: input reads ("<"), heredocs/herestrings
    ("<<"/"<<-"/"<<<"), file-descriptor duplications ("<&"/">&", whose
    target is an fd number, not a path), and writes whose literal target is
    a known inert sink ("/dev/null" etc.). Everything else -- writes and
    appends to a real file path, or any write whose target is non-literal
    and thus unverifiable -- is mutating and gates.  */
const redirectMutates = (redirect: Redirect): boolean => {
    switch (redirect.operator) {
        case "<":
        case "<<":
        case "<<-":
        case "<<<":
        case "<&":
        case ">&":
            /*  reads, heredocs, and fd duplications never write a file  */
            return false
        case ">":
        case ">>":
        case ">|":
        case "&>":
        case "&>>":
            /*  a write/append mutates unless its literal target is an
                inert sink; a non-literal target is unverifiable -> mutates  */
            if (redirect.target !== undefined
                && isLiteralWord(redirect.target)
                && INERT_SINKS.has(redirect.target.value))
                return false
            return true
        default:
            /*  "<>" (read-write) and anything unexpected -> fail safe  */
            return true
    }
}

/*  the running classification state threaded through the recursive walk  */
interface Walk {
    verdict:  Verdict
    reason?:  string
    /*  set once any hard safety gate trips (redirect, background, embedded
        substitution, non-literal name, risky assignment prefix): this caps
        the aggregate at "passthrough" so no such command is ever auto-allowed  */
    gated:    boolean
}

/*  the Bash classifier: parse the command into an AST and recursively walk
    the complete real "Node" union, classifying each resolved leaf command
    and aggregating the per-leaf verdicts under safety-first precedence and
    the hard safety gates. Wrapped by classifyBash() in a try/catch so any
    parse error, thrown exception, or unmatched leaf fails safe.  */
class Walker {
    private state: Walk = { verdict: "passthrough", gated: false }

    /*  trip a hard safety gate (downgrades any "allow" to "passthrough")  */
    private gate (): void {
        this.state.gated = true
    }

    /*  fold a leaf decision into the running aggregate, keeping the reason
        of whichever verdict currently dominates under safety-first precedence  */
    private add (decision: Decision): void {
        if (PRECEDENCE[decision.verdict] > PRECEDENCE[this.state.verdict]) {
            this.state.verdict = decision.verdict
            this.state.reason  = decision.reason
        }
    }

    /*  classify and walk a redirect: only a genuinely-mutating redirect
        (a write/append to a real file) is a hard gate -- benign reads,
        heredocs, fd duplications, and writes to inert sinks ("/dev/null")
        leave an inert command auto-approvable; a redirect target word may
        still embed a nested substitution and is always walked  */
    private walkRedirect (redirect: Redirect): void {
        if (redirectMutates(redirect))
            this.gate()
        if (redirect.target !== undefined)
            this.walkWord(redirect.target)
        if (redirect.body !== undefined)
            this.walkWord(redirect.body)
    }

    /*  walk a single word, descending into every nested Script embedded in
        its parts (command/process/arithmetic substitution); a word carrying
        any such substitution is also a hard gate (never auto-approvable)  */
    private walkWord (word: Word): void {
        if (word.parts === undefined)
            return
        for (const part of word.parts) {
            if (partHasScript(part))
                this.gate()
            if (part.type === "CommandExpansion" && part.script !== undefined)
                this.walkScript(part.script)
            else if (part.type === "ProcessSubstitution" && part.script !== undefined)
                this.walkScript(part.script)
            else if (part.type === "ArithmeticExpansion" && part.expression !== undefined)
                this.walkArithmetic(part.expression)
            else if (part.type === "ParameterExpansion") {
                /*  a parameter expansion may embed a substitution in its
                    default/alternate operand or its replace pattern, each a
                    nested word that must be walked and gated as well  */
                if (part.operand !== undefined) {
                    if (!isLiteralWord(part.operand))
                        this.gate()
                    this.walkWord(part.operand)
                }
                if (part.replace !== undefined) {
                    if (!isLiteralWord(part.replace.replacement))
                        this.gate()
                    this.walkWord(part.replace.pattern)
                    this.walkWord(part.replace.replacement)
                }
                if (part.slice !== undefined) {
                    this.walkWord(part.slice.offset)
                    if (part.slice.length !== undefined)
                        this.walkWord(part.slice.length)
                }
            }
            else if (part.type === "DoubleQuoted" || part.type === "LocaleString")
                for (const child of part.parts)
                    if (child.type === "CommandExpansion" && child.script !== undefined) {
                        this.gate()
                        this.walkScript(child.script)
                    }
                    else if (child.type === "ArithmeticExpansion" && child.expression !== undefined) {
                        this.gate()
                        this.walkArithmetic(child.expression)
                    }
        }
    }

    /*  walk an arithmetic expression, descending into any embedded command
        substitution ("$(( $(cmd) ))") which is itself a hard gate  */
    private walkArithmetic (expr: ArithmeticExpression): void {
        switch (expr.type) {
            case "ArithmeticBinary":
                this.walkArithmetic(expr.left)
                this.walkArithmetic(expr.right)
                break
            case "ArithmeticUnary":
                this.walkArithmetic(expr.operand)
                break
            case "ArithmeticTernary":
                this.walkArithmetic(expr.test)
                this.walkArithmetic(expr.consequent)
                this.walkArithmetic(expr.alternate)
                break
            case "ArithmeticGroup":
                this.walkArithmetic(expr.expression)
                break
            case "ArithmeticWord":
                break
            case "ArithmeticCommandExpansion":
                this.gate()
                if (expr.script !== undefined)
                    this.walkScript(expr.script)
                break
            default:
                /*  unknown arithmetic node -> fail safe (gate, do not approve)  */
                this.gate()
        }
    }

    /*  walk a risky assignment prefix ("FOO=$(cmd) cmd"): a prefix that
        assigns a substituted value is a hard gate and is itself traversed  */
    private walkPrefix (prefix: AssignmentPrefix): void {
        if (prefix.value !== undefined) {
            if (!isLiteralWord(prefix.value))
                this.gate()
            this.walkWord(prefix.value)
        }
        if (prefix.array !== undefined)
            for (const word of prefix.array) {
                if (!isLiteralWord(word))
                    this.gate()
                this.walkWord(word)
            }
    }

    /*  classify a leaf "Command" node: unwrap transparent wrappers and
        privilege escalators, walk every suffix word for embedded scripts,
        require a plain-literal command name, and classify the resolved
        name plus literal suffix tokens against the rule engine  */
    private walkCommand (command: BashCommand): void {
        /*  redirects and risky assignment prefixes are hard gates  */
        for (const redirect of command.redirects)
            this.walkRedirect(redirect)
        for (const prefix of command.prefix)
            this.walkPrefix(prefix)

        /*  a command without a literal name cannot be auto-approved  */
        if (command.name === undefined)
            return
        if (!isLiteralWord(command.name))
            this.gate()

        /*  every suffix word is walked for embedded substitutions  */
        for (const word of command.suffix)
            this.walkWord(word)

        /*  reconstruct the literal "[name, ...args]" token stream, stopping
            the trustworthy literal args at the first non-literal word  */
        let name = command.name.value
        const args: string[] = []
        for (const word of command.suffix) {
            if (!isLiteralWord(word))
                break
            args.push(word.value)
        }

        /*  unwrap transparent wrappers ("env"/"xargs"/...) and privilege
            escalators ("sudo"/"doas") to the real inner command; privilege
            escalation caps the verdict at "ask" but still classifies inner  */
        let privileged = false
        while (WRAPPERS.has(name) || PRIVILEGE.has(name)) {
            if (PRIVILEGE.has(name))
                privileged = true
            /*  drop the wrapper's own flags and any "VAR=val" arguments,
                then take the next bare token as the inner command name  */
            let i = 0
            while (i < args.length && (args[i].startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(args[i])))
                i++
            if (i >= args.length) {
                /*  bare wrapper with no inner command -> nothing to approve  */
                name = ""
                args.length = 0
                break
            }
            name = args[i]
            args.splice(0, i + 1)
        }

        if (name === "")
            return

        /*  classify the resolved leaf and fold in the decision, capping at
            "ask" when a privilege escalator wrapped this command  */
        const decision = classifyLeaf(name, args)
        if (privileged && PRECEDENCE[decision.verdict] < PRECEDENCE["ask"])
            this.add({ verdict: "ask", reason: "privilege escalation requires confirmation" })
        else
            this.add(decision)
    }

    /*  recursively visit the complete real "Node" union via an exhaustive
        switch with a TypeScript "never" exhaustiveness guard, so a future
        unbash node type fails the build rather than slipping through  */
    private walkNode (node: Node): void {
        switch (node.type) {
            case "Command":
                this.walkCommand(node)
                break
            case "Pipeline":
                for (const cmd of node.commands)
                    this.walkNode(cmd)
                break
            case "AndOr":
                for (const cmd of node.commands)
                    this.walkNode(cmd)
                break
            case "If":
                this.walkNode(node.clause)
                this.walkNode(node.then)
                if (node.else !== undefined)
                    this.walkNode(node.else)
                break
            case "For":
                for (const word of node.wordlist)
                    this.walkWord(word)
                this.walkNode(node.body)
                break
            case "ArithmeticFor":
                if (node.initialize !== undefined)
                    this.walkArithmetic(node.initialize)
                if (node.test !== undefined)
                    this.walkArithmetic(node.test)
                if (node.update !== undefined)
                    this.walkArithmetic(node.update)
                this.walkNode(node.body)
                break
            case "Select":
                for (const word of node.wordlist)
                    this.walkWord(word)
                this.walkNode(node.body)
                break
            case "While":
                this.walkNode(node.clause)
                this.walkNode(node.body)
                break
            case "Function":
                this.walkNode(node.body)
                for (const redirect of node.redirects)
                    this.walkRedirect(redirect)
                break
            case "Subshell":
                this.walkNode(node.body)
                break
            case "BraceGroup":
                this.walkNode(node.body)
                break
            case "CompoundList":
                this.walkCompoundList(node)
                break
            case "Case":
                this.walkWord(node.word)
                for (const item of node.items)
                    this.walkNode(item.body)
                break
            case "Coproc":
                this.walkNode(node.body)
                for (const redirect of node.redirects)
                    this.walkRedirect(redirect)
                break
            case "TestCommand":
                /*  test expressions take no auto-approval verdict, but their
                    operand words may embed a substitution that must be walked
                    and gated, so descend into the whole test expression  */
                this.walkTest(node.expression)
                break
            case "ArithmeticCommand":
                if (node.expression !== undefined)
                    this.walkArithmetic(node.expression)
                break
            case "Statement":
                this.walkStatement(node)
                break
            default:
                /*  exhaustiveness guard: a future unbash node type makes
                    this a compile-time error; at runtime, fail safe  */
                this.exhaustive(node)
        }
    }

    /*  walk a "Statement": background "&" and statement-level redirects are
        hard gates, then descend into the wrapped command node  */
    private walkStatement (statement: Statement): void {
        if (statement.background === true)
            this.gate()
        for (const redirect of statement.redirects)
            this.walkRedirect(redirect)
        this.walkNode(statement.command)
    }

    /*  walk a "TestCommand" expression, descending into every operand
        word so an embedded substitution is gated and never auto-approved  */
    private walkTest (expr: TestExpression): void {
        switch (expr.type) {
            case "TestUnary":
                this.walkWord(expr.operand)
                break
            case "TestBinary":
                this.walkWord(expr.left)
                this.walkWord(expr.right)
                break
            case "TestLogical":
                this.walkTest(expr.left)
                this.walkTest(expr.right)
                break
            case "TestNot":
                this.walkTest(expr.operand)
                break
            case "TestGroup":
                this.walkTest(expr.expression)
                break
        }
    }

    /*  walk a "CompoundList" (a sequence of statements)  */
    private walkCompoundList (list: CompoundList): void {
        for (const statement of list.commands)
            this.walkNode(statement)
    }

    /*  walk a parsed "Script" (the top-level and every nested one)  */
    private walkScript (script: Script): void {
        for (const statement of script.commands)
            this.walkNode(statement)
    }

    /*  compile-time exhaustiveness assertion; the "never" parameter makes
        an unhandled node type a build error, while the runtime gate keeps
        an unexpected node from ever being auto-approved  */
    private exhaustive (_node: never): void {
        this.gate()
    }

    /*  classify a whole parsed script and return the aggregate decision,
        downgrading any "allow" to "passthrough" when a hard gate tripped  */
    classify (script: Script): Decision {
        this.walkScript(script)
        if (this.state.gated && this.state.verdict === "allow")
            return { verdict: "passthrough" }
        return { verdict: this.state.verdict, reason: this.state.reason }
    }
}

/*  classify a raw "Bash" command string into an "allow"/"ask"/"deny"/
    "passthrough" decision. The whole classification is fail-safe: any parse
    error, thrown exception, or unmatched/unexpected construct yields
    "passthrough" so the host agent's default prompt flow takes over.
    Never crashes, never auto-approves on doubt.  */
export const classifyBash = (command: string): Decision => {
    try {
        const script = parse(command)
        if (script.errors !== undefined && script.errors.length > 0)
            return { verdict: "passthrough" }
        return new Walker().classify(script)
    }
    catch (_e) {
        /*  fail safe on any unexpected parser or walker error  */
        return { verdict: "passthrough" }
    }
}
