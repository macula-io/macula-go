# Contributing

## Nesting limit

A function body may hold one nesting construct and nothing inside it.

This is the limit the Erlang `macula` library enforces with Elvis
(`no_deep_nesting` at level 2), carried over to every SDK so the code reads
the same way in every language. Flatten deeper code with guard clauses, early
returns and small named functions.

This repository checks it with golangci-lint 2.13.2, using revive's
`max-control-nesting` rule at 1 (see `.golangci.yml`). Test files are not
checked. Run it locally:

    golangci-lint run --tests=false ./...

The setting is calibrated against seven shapes shared by every SDK. Elvis is
the reference; the last column is what this repository's check reports.

| Shape | Code | Elvis level 2 | revive max-control-nesting 1 |
|---|---|---|---|
| S1 | no control structure | pass | pass |
| S2 | one `if` | pass | pass |
| S3 | an `if` inside an `if` | fail | fail |
| S4 | three levels of `if` | fail | fail |
| S5 | a closure in the function body | pass | pass |
| S6 | a closure inside an `if` | fail | pass |
| S7 | an `if` inside a closure | fail | pass |

revive starts counting again inside a closure, so it passes S6 and S7, which
Elvis fails. Treat those two shapes as failures in review.

For now the CI job counts violations without failing the build. It will fail
the build once the existing code has been flattened.
