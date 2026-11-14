# Contributing

Thanks for helping make Sentinel better.

## Reporting bugs and false alarms

[Open an issue](https://github.com/tsxmamii/sentinel/issues/new/choose).
False alarms (normal requests that Sentinel refuses) are especially useful:
include the log line, which shows the rule, the field and the matched text.
Remove anything private (tokens, cookies, personal data) first.

Security problems go through [`SECURITY.md`](SECURITY.md), never a public
issue.

## Code changes

Small, focused pull requests are easiest to review. Before you start on
something big, open an issue so we can agree on the approach.

```bash
cd gateway
gofmt -l cmd internal       # must print nothing
go vet ./...
go test ./...
```

Dependencies are vendored (`gateway/vendor/`); builds need no network. CI
runs the same checks, plus fuzzing, the Core Rule Set suite and a Docker
smoke test.

## Contributor agreement

Sentinel is source-available under the [PolyForm Shield License](LICENSE.md),
and its maintainer also offers commercial editions. So that your
contribution can be used in every edition, by opening a pull request you
agree that:

1. the contribution is your own work, or you have the right to submit it;
2. you grant Saif Zahid a perpetual, worldwide, irrevocable, royalty-free
   license to use, change, distribute and sublicense it, including in
   commercial editions of Sentinel and under other licenses;
3. you keep the copyright in your contribution.

If you can't agree to this (for example because of your employer), please
open an issue instead of a pull request.
