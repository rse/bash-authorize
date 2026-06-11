/*!
**  bash-authorize -- Claude Code "PreToolUse" hook for authorizing Bash commands
**  Copyright (c) 2026 Dr. Ralf S. Engelschall <rse@engelschall.com>
**  Distributed under MIT license <https://spdx.org/licenses/MIT.html>
*/

/*  built-in dependencies  */
import assert           from "node:assert/strict"

/*  unit under test (the pure classifier API, free of any CLI side-effects)  */
import { classifyBash } from "./bash-authorize-api.js"
import type { Verdict } from "./bash-authorize-api.js"

/*  assert that a Bash command string classifies to the expected verdict  */
const expectVerdict = (command: string, verdict: Verdict): void => {
    const decision = classifyBash(command)
    assert.equal(decision.verdict, verdict,
        `expected "${command}" to classify as "${verdict}" but got "${decision.verdict}"`)
}

describe("bash-authorize", () => {
    describe("the four verdicts", () => {
        it("auto-approves a genuinely-inert command as \"allow\"", () => {
            expectVerdict("ls", "allow")
            expectVerdict("ls -la /tmp", "allow")
            expectVerdict("pwd", "allow")
            expectVerdict("cat README.md", "allow")
            expectVerdict("echo hello world", "allow")
        })
        it("forces a prompt on a known-dangerous command as \"ask\"", () => {
            expectVerdict("rm -rf build", "ask")
            expectVerdict("chmod 777 file", "ask")
            expectVerdict("kill -9 1234", "ask")
        })
        it("blocks a catastrophic command outright as \"deny\"", () => {
            expectVerdict("rm -rf /", "deny")
            expectVerdict("mkfs.ext4 /dev/sda1", "deny")
            expectVerdict("dd if=/dev/zero of=/dev/sda", "deny")
        })
        it("defers an unrecognized command via \"passthrough\"", () => {
            expectVerdict("frobnicate --wibble", "passthrough")
            expectVerdict("make build", "passthrough")
        })
    })

    describe("decision reasons", () => {
        it("returns the rule's human-readable reason alongside the verdict", () => {
            assert.deepEqual(classifyBash("ls"),
                { verdict: "allow", reason: "directory listing is read-only" })
            assert.deepEqual(classifyBash("rm -rf /"),
                { verdict: "deny", reason: "recursive forced removal of root is catastrophic" })
        })
        it("carries no meaningful reason for a bare \"passthrough\"", () => {
            assert.deepEqual(classifyBash("frobnicate"), { verdict: "passthrough", reason: undefined })
        })
    })

    describe("ordered rules (first match wins)", () => {
        it("denies \"rm -rf /\" before the broader \"rm -rf\" ask rule fires", () => {
            expectVerdict("rm -rf /", "deny")
            expectVerdict("rm -rf ./build", "ask")
        })
        it("recognizes the \"mkfs\" command family by its dotted suffix", () => {
            expectVerdict("mkfs", "deny")
            expectVerdict("mkfs.vfat /dev/sdb1", "deny")
        })
        it("denies a raw device write only when the target is a device", () => {
            expectVerdict("dd of=/dev/sda", "deny")
            expectVerdict("dd of=backup.img", "passthrough")
        })
    })

    describe("allow rules", () => {
        it("matches a multi-token allow prefix but not a sibling subcommand", () => {
            expectVerdict("git status", "allow")
            expectVerdict("git status -s", "allow")
            expectVerdict("git log --oneline", "allow")
            expectVerdict("git commit -m x", "passthrough")
        })
        it("downgrades an inert command to passthrough on a denied flag", () => {
            expectVerdict("grep pattern file", "allow")
            expectVerdict("grep -r pattern .", "passthrough")
            expectVerdict("find . -type f", "allow")
            expectVerdict("find . -delete", "passthrough")
        })
        it("downgrades \"node\" when given an inline eval/print flag", () => {
            expectVerdict("node script.js", "allow")
            expectVerdict("node -e 'process.exit(1)'", "passthrough")
            expectVerdict("node --eval code", "passthrough")
        })
        it("downgrades awk when its program text carries a side-effect", () => {
            expectVerdict("awk '{ print $1 }' file", "allow")
            expectVerdict("awk 'BEGIN { system(\"rm x\") }'", "passthrough")
            expectVerdict("awk '{ print > \"out\" }' file", "passthrough")
        })
        describe("the curl/wget no-file-output rules", () => {
            it("auto-approves curl when it streams to stdout only", () => {
                expectVerdict("curl https://example.com", "allow")
                expectVerdict("curl -fsSL https://example.com/x", "allow")
                expectVerdict("curl -H 'Accept: application/json' https://api.example.com", "allow")
            })
            it("downgrades curl when it would write a file", () => {
                expectVerdict("curl -o out.html https://example.com", "passthrough")
                expectVerdict("curl -O https://example.com/file.tgz", "passthrough")
                expectVerdict("curl --output out https://example.com", "passthrough")
                expectVerdict("curl --output=out https://example.com", "passthrough")
                expectVerdict("curl -sSL -D headers.txt https://example.com", "passthrough")
                expectVerdict("curl https://example.com > out.html", "passthrough")
            })
            it("auto-approves wget only with an explicit stdout output document", () => {
                expectVerdict("wget -O - https://example.com", "allow")
                expectVerdict("wget -qO- https://example.com", "allow")
                expectVerdict("wget --output-document=- https://example.com", "allow")
                expectVerdict("wget --output-document - https://example.com", "allow")
            })
            it("downgrades wget when it would write a file (its default)", () => {
                expectVerdict("wget https://example.com", "passthrough")
                expectVerdict("wget -q https://example.com", "passthrough")
                expectVerdict("wget -O file https://example.com", "passthrough")
                expectVerdict("wget -qO file https://example.com", "passthrough")
                expectVerdict("wget -r -O - https://example.com", "passthrough")
                expectVerdict("wget -e output_document=x https://example.com", "passthrough")
                expectVerdict("wget -O - https://example.com > out.html", "passthrough")
            })
        })
        describe("the sed argGuard", () => {
            it("allows a verified-safe inert sed script", () => {
                expectVerdict("sed 's/foo/bar/' file", "allow")
                expectVerdict("sed -n '1,10p' file", "allow")
                expectVerdict("sed '/^#/d' file", "allow")
            })
            it("rejects a sed script that writes, reads, or executes", () => {
                expectVerdict("sed 's/foo/bar/w out' file", "passthrough")
                expectVerdict("sed '1e rm -rf x' file", "passthrough")
                expectVerdict("sed -i 's/a/b/' file", "passthrough")
                expectVerdict("sed -f script.sed file", "passthrough")
            })
        })
    })

    describe("risk rules (every present predicate must hold)", () => {
        it("requires the recursive AND force flags for the rm ask rule", () => {
            expectVerdict("rm -rf x", "ask")
            expectVerdict("rm -r x", "passthrough")
            expectVerdict("rm -f x", "passthrough")
        })
        it("folds long-form flag aliases onto their canonical short flag", () => {
            expectVerdict("rm --recursive --force x", "ask")
            expectVerdict("rm -R --force x", "ask")
        })
        it("matches a git subcommand by an order-independent positional token", () => {
            expectVerdict("git push", "ask")
            expectVerdict("git push origin main", "ask")
            expectVerdict("git pull", "passthrough")
        })
        it("treats the root token literally so \"rm -rf x\" is not catastrophic", () => {
            expectVerdict("rm -rf /", "deny")
            expectVerdict("rm -rf /home", "ask")
        })
    })

    describe("hard safety gates (downgrade any allow to passthrough)", () => {
        it("gates an inert command writing to a real file", () => {
            expectVerdict("ls > out.txt", "passthrough")
            expectVerdict("echo hi >> log", "passthrough")
        })
        it("does not gate a benign read or an inert sink redirect", () => {
            expectVerdict("cat < input.txt", "allow")
            expectVerdict("ls > /dev/null", "allow")
            expectVerdict("grep x file 2>/dev/null", "allow")
        })
        it("gates an embedded command substitution whose inner script is not inert", () => {
            expectVerdict("echo `whoami`", "passthrough")
            expectVerdict("cat $(make build)", "passthrough")
        })
        it("gates a non-literal command name", () => {
            expectVerdict("$CMD --flag", "passthrough")
        })
        it("gates a substituted assignment prefix whose inner script is not inert", () => {
            expectVerdict("FOO=$(id) ls", "passthrough")
        })
    })

    describe("recursive-allow command substitution", () => {
        it("allow backgrounded command", () => {
            expectVerdict("ls &", "allow")
        })
        it("auto-approves a command substitution whose inner script is inert", () => {
            expectVerdict("cat $(find . -name x)", "allow")
            expectVerdict("echo $(basename /a/b)", "allow")
            expectVerdict("skill=$(basename $(dirname /a/b/c))", "allow")
        })
        it("still gates when the inner script is dangerous or unknown", () => {
            expectVerdict("echo $(chmod 777 x)", "ask")
            expectVerdict("cat $(rm -rf /)", "deny")
            expectVerdict("echo $(frobnicate)", "passthrough")
        })
        it("keeps gating process and arithmetic substitutions unconditionally", () => {
            expectVerdict("cat <(ls)", "passthrough")
            expectVerdict("echo $(( $(ls | wc -l) + 1 ))", "passthrough")
        })
        it("auto-approves the newly-added inert path/text helpers", () => {
            expectVerdict("basename /a/b/c", "allow")
            expectVerdict("dirname /a/b/c", "allow")
            expectVerdict("realpath .", "allow")
            expectVerdict("readlink -f /a/b", "allow")
            expectVerdict("tr a-z A-Z", "allow")
            expectVerdict("cut -d: -f1 /etc/passwd", "allow")
            expectVerdict("uniq file", "allow")
        })
        it("gates uniq when given a second positional output-file operand", () => {
            expectVerdict("uniq input output", "passthrough")
            expectVerdict("uniq -f 2 input", "allow")
        })
        it("auto-approves a realistic for-loop with substitutions, sed, grep, and sort", () => {
            const cmd = "for f in /a/*/SKILL.md; do " +
                "skill=$(basename $(dirname \"$f\")); " +
                "arg2=$(sed -n '1,10p' \"$f\" | grep arg2= | sed 's/x/y/'); " +
                "if [ -n \"$arg2\" ]; then echo \"$skill: $arg2\"; fi; " +
                "done | sort"
            expectVerdict(cmd, "allow")
        })
    })

    describe("the \".env\" secrets-file deny gate", () => {
        it("denies reading a \".env\" file by any inert command", () => {
            expectVerdict("cat .env", "deny")
            expectVerdict("cat ./.env", "deny")
            expectVerdict("cat config/.env", "deny")
            expectVerdict("cat /home/x/.env", "deny")
            expectVerdict("head -5 .env", "deny")
            expectVerdict("tail .env", "deny")
            expectVerdict("grep SECRET .env", "deny")
        })
        it("denies even a command that would otherwise be passthrough", () => {
            expectVerdict("source .env", "deny")
            expectVerdict("frobnicate .env", "deny")
        })
        it("denies a redirect whose target is a \".env\" file", () => {
            expectVerdict("cat < .env", "deny")
            expectVerdict("grep x file < .env", "deny")
        })
        it("denies through transparent wrappers and privilege escalators", () => {
            expectVerdict("xargs cat .env", "deny")
            expectVerdict("sudo cat .env", "deny")
            expectVerdict("env FOO=bar cat .env", "deny")
        })
        it("denies when a \".env\" reference appears anywhere in a list or pipeline", () => {
            expectVerdict("ls && cat .env", "deny")
            expectVerdict("cat .env | grep KEY", "deny")
        })
        it("does NOT deny sibling names that merely share the prefix/suffix", () => {
            expectVerdict("cat .env.example", "allow")
            expectVerdict("cat .env.local", "allow")
            expectVerdict("cat .envrc", "allow")
            expectVerdict("cat environment", "allow")
            expectVerdict("cat my.env.txt", "allow")
        })
        it("reports the \".env\" deny reason", () => {
            assert.deepEqual(classifyBash("cat .env"),
                { verdict: "deny", reason: "reference to a \".env\" secrets file is blocked" })
        })
    })

    describe("transparent wrappers", () => {
        it("unwraps to the inner command and classifies that", () => {
            expectVerdict("env FOO=bar ls", "allow")
            expectVerdict("xargs rm -rf /", "deny")
            expectVerdict("nohup cat file", "allow")
        })
        it("defers a bare wrapper with no inner command", () => {
            expectVerdict("env", "passthrough")
        })
    })

    describe("privilege escalation", () => {
        it("caps an otherwise-inert inner command at \"ask\"", () => {
            expectVerdict("sudo ls", "ask")
            expectVerdict("doas cat file", "ask")
        })
        it("still lets an inner catastrophic command escalate to \"deny\"", () => {
            expectVerdict("sudo rm -rf /", "deny")
        })
    })

    describe("verdict aggregation (safety-first precedence)", () => {
        it("lets the strongest verdict across a pipeline or list win", () => {
            expectVerdict("ls | cat", "allow")
            expectVerdict("ls && rm -rf /", "deny")
            expectVerdict("cat file && git push", "ask")
            expectVerdict("ls ; chmod 777 x ; pwd", "ask")
        })
    })

    describe("fail-safe behavior", () => {
        it("passes through on a parse error rather than crashing", () => {
            expectVerdict("ls 'unterminated", "passthrough")
            expectVerdict("(", "passthrough")
        })
        it("passes through on an empty command", () => {
            expectVerdict("", "passthrough")
            expectVerdict("   ", "passthrough")
        })
        it("never throws regardless of the input", () => {
            const inputs = [ "", "&&&", "$(", "rm -rf /", "ls", "{{{", ">>>", "|||" ]
            for (const input of inputs)
                assert.doesNotThrow(() => classifyBash(input))
        })
    })
})
