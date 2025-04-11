# Test Registries

## Crypto Agility Test

`cryptotest` is a CLI tool to test if a registry has crypto agility of supporting various hash algorithms.
It produces a report in markdown format.

> [!NOTE]
> Testing a registry requires pull and push permissions.

Execute the command below to test a registry.

```sh
cryptotest --registry my.registry.example
```

Execute the command below to test a local registry.

```sh
cryptotest --registry localhost:5000 --plain-http
```

The output can be written to a file using `--output`:

```sh
cryptotest --registry localhost:5000 --plain-http --output report.md
```

It is also possible to test an auth-enabled registry.

```sh
cryptotest --registry my.registry.example --username $user --password $pass
cryptotest --registry my.registry.example --identity-token $token
```