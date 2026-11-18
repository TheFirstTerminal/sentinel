# Contributing

Sentinel's code is public so you can read it, check how it protects your
apps and trust what it does. It is not open for code contributions: pull
requests are not accepted.

What helps, and is very welcome:

## Reporting bugs and false alarms

[Open an issue](https://github.com/TheFirstTerminal/sentinel/issues/new/choose).
False alarms (normal requests that Sentinel refuses) are especially useful:
include the log line, which shows the rule, the field and the matched text.
Remove anything private (tokens, cookies, personal data) first.

## Reporting security problems

Privately, as described in [`SECURITY.md`](SECURITY.md), never in a public
issue. A way past Sentinel's checks counts.

## Reviewing the code

Read it, question it, and tell us what you find: a weak spot, a rule that
misses a variant, a claim in the docs the code doesn't back up. Open an
issue (or a private report, if it's a security problem) and point to the
file and line.

## Running the checks yourself

```bash
cd gateway
go vet ./...
go test ./...
```

Dependencies are vendored (`gateway/vendor/`), so this needs no network.
