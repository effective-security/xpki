> **Go→Rust migration:** Use the go2rs workspace at `../rust/go2rs/migration.code-workspace` and its root `AGENTS.md` plus `.cursor/skills/go2rs-migrate/SKILL.md`. Below are the Go coding guidelines for xpki.

# CODING GUIDELINES

1. When creating Unit Test always use `require` and `assert` from "github.com/stretchr/testify"

- use `require` is test can't continue and need to fail
- use `assert` when test can continue and print failed cases

2. Tests should be table‑driven and use `t.Run` when applicable.
3. Tests should use `t.Parallel` when appropriate.
4. To return an error always use "github.com/pkg/errors" package:
   Use `Wrap`, `Wrapf` to wrap errors from external packages that do not wrap an error.
   Use `WithMessage`, `WithMessagef` to annotate a wrapped error.
   Use `errors.Errorf` or `errors.New` to return new error.
5. Use `make test` to test, no approval needed.
6. Use `make lint` to check format and lint errors, no approval needed.
7. When creating code use `cockroachdb/errors` package to return errors
   - Use `Wrap`, `Wrapf` to wrap external or unwrapped errors
   - Use `WithMessage`, and `WithMessagef` for annotation on wrapped errors from `effective-security` repos

# Important

- Do not use `git` commands to commit or reset branch until explicitly instructed.
- Continue until success or stop for clarification or help
