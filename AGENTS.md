# AGENTS

Guidance for coding agents working in this repository.

## Scope and priorities

- Keep changes minimal and targeted. Feel free to do light refactors that are relevant to the modifications.
- Breaking changes:
  - Do not introduce breaking usage behavior (cli flags, environment variables, etc.) unless explicitly agreed.
  - Do not introduce breaking changes for the Go API in the `pkg/` directory.
  - If a compatibility break seems beneficial, stop and ask for confirmation before implementing it.
- Update or add tests when behavior changes.

## Go coding conventions

### General guidelines

- Use explicit, descriptive variable names by default.
  - Notable bad examples: `req`, `resp`, `cfg`, `v`
  - Allowed short-name exceptions:
    - indexes such as `i`, `j`
    - `ctx` for `context.Context`
    - `t` for `*testing.T` and `b` for `*testing.B`
    - `ctrl` for `*gomock.Controller`
    - `err` for `error`, `errs` for `[]error`
    - `wg` for `*sync.WaitGroup`
- Avoid using global variables except for:
  - exported sentinel errors that are used outside the package boundaries
  - regular expressions defined with `regexp.MustCompile`
  - variables set by the build pipeline, such as `Version` and `BuildDate`
- Constants
  - Prefer defining them inline in a function if it's only used in that function, rather than at the package level.
  - Each one should be defined right above where it's used, instead of having multiple defined at the same place in a `const ()` block
  - If one is only used in a single production code function, define it right above it so it's more local for readability.
  - Do not define constants when constants exist in other packages, for example `http.StatusBadRequest` or `log.LevelDebug`.
- Structs
  - Prefer defining them inline in a function if it's only used in that function, rather than at the package level.
- Do not use the short if form, prefer the longer one
- Follow modern Go, according to the Go version defined in go.mod. Prefer modern constructs when equivalent:
  - Example: use `for i := range 5` rather than `for i := 0; i < 5; i++`.
  - Example: use `new("string")` rather than helper wrappers such as `stringPtr("string")`.
  - Example: no need to pin variables in for loops when using them in goroutines or subtests.
- Use `New(...) *Item` constructor per package. Each package should ideally only have one constructor, although this is not a strict rule. The constructor should return a pointer to the struct, and not an interface.
- Always prefer using context-aware functions, for example:
  - `exec.CommandContext` rather than `exec.Command`
  - `http.NewRequestWithContext` rather than `http.NewRequest`
- Never export a symbol unless absolutely necessary.
- Always use the most restrictive builtin types. For example prefer `uint` over `int` if it's only zero or positive. Prefer `uint16` is the max value is 65535.
- Prefer using builtin types whenever possible AND do not define single field structs unless necessary
- Prefer splitting a code line only when it triggers the `lll` linter, do not split a command or arguments list for each element
- Use `netip` types instead of `net` types whenever possible
- Use constants instead of variables whenever possible, especially function-local inline constants.
- Do not use `time.Sleep`, prefer using a `time.Timer` with a `select` statement also listening on a context cancelation
- `panic`:
  - should only be used when a programming error is encountered and you should NOT return errors for programming errors (such as passing nil objects)
  - Its counterpart `recover` should not really be used, except for testing a panic in test code (or use `assert.PanicsWithValue`).

### Directory structure and file naming

- Executable main packages with a single `main()` function must be in the `cmd` directory.
  Prefer having top level logic and have a longer `main()` function rather than having an `internal/app` package.
- Code lives by default in subpackages within the `internal` directory
- Code needing to be imported by external Go modules must be in subpackages within the `pkg` directory
- Example code especially using the `pkg` directory must be in `main` packages within the `examples` directory, each with a single `main.go` function.
- If AND only if the repository is a Go library and not a Go application, you may have Go files at the root of the project to simplify import paths. Most of the code should still be in subpackages in the `internal` directory.
- Interfaces should be defined in `interfaces.go` files for each package. If there are unexported interfaces which need to be mocked, which is rare, they should be defined in `interfaces_local.go` files.
- Mock files are
  - `mocks_generate_test.go` which only contains `//go:generate` directives for generating mocks, and no actual code
  - `mocks_test.go` which contains the generated mocks from exported interfaces and no other code, and is ignored in coverage reports
  - `mocks_local_test.go` (rare) which contains the generated mocks from unexported interfaces and no other code, and is ignored in coverage reports
  - NEVER generate an exported mock in a non test file, prefer re-generating files across packages.
- Package naming
  - Your package name should be the same as the directory containing it, **except for the `main` package**
  - Use single words for package names
  - Do not use generic names for package names such as `utils` or `helpers`
- Package nesting
  - Try to avoid nesting packages by default
  - You can nest packages if you have different implementations for the same interface (e.g. a store interface)
  - You can nest packages if you start having a lot of Go files (more than 10) and it really does make sense to make subpackages

### Linting

The linter is `golangci-lint` with the configuration defined in `.golangci.yml`.

To exclude code from linting, prefer using, when absolutely necessary, command comments `//nolint:<linter>`.
This allows the `nolintlint` linter to detect and report unnecessary `//nolint` comments later.
You can notably use `//nolint:lll` and, for good valid reasons, `//nolint:gosec`. Sometimes `//nolint:mnd` when it just doesn't make sense to extract a constant such as `n = n << 4`
Always prefer placing `//nolint` comments on the same code line where the error comes from, and not above a code block.

### Mocking

Mocking works with the `go.uber.org/mock` library, and the `mockgen` tool.

- Mocks from exported interfaces are generated using go generate commands in `mocks_generate_test.go` files, and stored in `mocks_test.go` files, using:

    ```go
    //go:generate mockgen -destination=mocks_test.go -package=$GOPACKAGE . InterfaceA,InterfaceB
    ```

- Mocks from unexported interfaces are generated using go generate commands in `mocks_generate_test.go` files, and stored in `mocks_local_test.go` files. The source file for unexported interfaces is `interfaces_local.go`. The go generate command is similar to:

    ```go
    //go:generate mockgen -destination=mocks_local_test.go -package $GOPACKAGE -source interfaces_local.go
    ```

- Mocks from external interfaces are generated using go generate commands in `mocks_generate_test.go` files, and stored in `mocks_<package-name>_test.go` files, using:

    ```go
    //go:generate mockgen -destination=mocks_<package-name>_test.go -package $GOPACKAGE module-name InterfaceA,InterfaceB
    ```

- Generated mocks usage in tests:
  - Define mocks in the subtest, not in the parent test. You can also have a function returning the mocks as a field of the test case struct, which takes in the subtest `*testing.T` as argument, and call it in the subtest to get the mocks.
  - **Never** use `gomock.Any()` as argument. Always use concrete, precise arguments. You might need to define a custom GoMock matcher for your argument in some very niche and corner cases.
  - **Never** use `.AnyTimes()` on mocks. Always define the number of times a certain mock call should be called, with `.Times(3)` for example.
  - **Always** set the `.Return(...)` on the mock if the function returns something.
  - Avoid using **mock helpers** functions, prefer a bit of repetition than tight coupling and dependency

### main.go

- Make the program OS signal aware, so it attempts a graceful shutdown when interruped. Force quit the program on a second interrupt signal.

### Formatting

The Go formatter used is gofumpt.

### Errors

- Always prefer wrapping errors with some context with `fmt.Errorf("doing this: %w", err)`
- In rare cases, you can just use `return err` notably:
  - If the function is called **recursively**, since we don't wrap the wrapping multiple times for each recursion
  - If the current function only statement is the call to another function, for example:

      ```go
      func (s *Struct) Fetch() error {
        return fetch() // do not wrap the error
      }
      ```

- When wrapping errors, use verbs ending in "ing" and no "failed to" or "cannot" to avoid redundancy. For example, use `fmt.Errorf("resolving host: %w", err)` rather than `fmt.Errorf("failed to resolve host: %w", err)`.
- When wrapping an error, the context should NEVER contain variables injected as arguments in the function returning an error, to avoid repeating the same variable in multiple error messages.
- Testing errors:
  - If the error does not wrap a sentinel error, use `assert.ErrorContains` to check for error messages, rather than `assert.EqualError`, to avoid having to update tests for minor changes in error messages. And use `assert.NoError` to check for no error.
  - If the error wraps a sentinel error, use `assert.ErrorIs` to check both for the sentinel error or an expected nil error. You can also check the error message with `assert.ErrorContains`

### User program settings

- For configuration structs, each field Go zero value (i.e. `0` for `int`, `nil` for `*string`) should be an INVALID value in the user sense. This is used to detect when a field is not set, in order to default it, merge it or override it. For example if `""` is not a valid value, the field should be of type `string`. Conversely, if `""` is a valid value, the field should be of type `*string` to distinguish between "not set" and "set to empty string". Notably, boolean fields are ALWAYS of type `*bool` for this reason, since both `true` and `false` are valid values.
- Configuration reading and handling relies on the Go library github.com/qdm12/gosettings please use it whenever appropriate.
  - Do not wrap errors coming from `reader.Reader` methods, since they already contain the necessary context.
  - All keys passed to `reader.Reader` methods must be in environment variable format, i.e. uppercase with underscores. These get converted to lowercase and dashes for flags notably.
- For each settings structs, define the following methods, which are usually unexported, but can be exported especially for the top level Settings struct, in this order:
  - `func (s *Settings) setDefaults()` whichs sets defaults (using `gosettings.Default*` functions) on unset fields
  - If the settings need to be patched at runtime, which is rarely the case, define `func (s *Settings) overrideWith(other Settings)` which overrides the settings with another settings struct, only for fields that are set in the other struct (using `gosettings.OverrideWith` functions).
  - `func (s Settings) validate() error` which validates the settings, and returns an error if anything is invalid
  - `func (s *Settings) read(r *reader.Reader) error` which reads the settings from a gosettings/reader.Reader (which can be from multiple sources, such as environment variables, cli flags, config files etc.)
  - `func (s Settings) String() string` which uses `toLinesNode().String()` to return a string representation of the settings
  - `func (s Settings) toLinesNode() *gotree.Node` which a github.com/qdm12/gotree `*Node` representing the settings

### Testing

- Use the github.com/stretchr/testify library for assertions
- Most tests should be table tests with parallel subtests
- Prefer map-based table tests of the form `map[string]struct{ ... }`, with the key as the test name.
  Use underscores in test names, not spaces, to keep `go test` output searchable.
- Use `testCases` for the table variable name, and `testCase` for each iterated case value.
- Run all tests in parallel:
  - call `t.Parallel()` in the top-level test
  - call `t.Parallel()` in each subtest

### Libraries to use

- Logging: `github.com/qdm12/log`
- Splash information at program start: `github.com/qdm12/gosplash`
- Long running services (i.e. health server, http prod server, backup loop etc.): `github.com/qdm12/goservices`
- String tree structures: `github.com/qdm12/gotree`

### Extra rules

- Do not use `http.DefaultClient`, use a custom `*http.Client` with a fixed timeout and share with dependency injections.
- Do not check for injected dependencies being `nil`, prefer to just panic on a nil pointer. By default it's fine to panic if a developer injects a dependency `nil`. `nil` does not mean use a default.

## Validation checklist

Run the following before finishing changes:

1. Go building `go build ./...`
1. Go linting `golangci-lint run`
1. Go unit tests `go test ./...`
1. If a module is added or modified, run `go mod tidy`
1. If an interface or mock command is modified, run `go generate -run mockgen ./...`

If a Markdown file is modified and `markdownlint-cli2` is available, run `markdownlint-cli2 "**/*.md"`

If a command is unavailable in the current environment, report it clearly and provide the exact command needed once available.
