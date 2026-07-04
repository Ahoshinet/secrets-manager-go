# secrets-manager-go

Native Go client for the [Secrets Manager](https://github.com/Ahoshinet/secrets-manager)
HTTP API. In-process — fetch secrets directly in your Go program instead of
shelling out to the `secrets` CLI.

The wire contract this client targets is documented in the server repository at
[`docs/API.md`](https://github.com/Ahoshinet/secrets-manager/blob/main/docs/API.md).

## Install

```bash
go get github.com/Ahoshinet/secrets-manager-go@latest
```

```go
import secrets "github.com/Ahoshinet/secrets-manager-go"
```

## Usage

```go
client, err := secrets.New(secrets.Config{
	ServerURL: "https://secrets.example.com",
	Token:     token,
})
if err != nil {
	return err
}

values, err := client.GetSecrets(ctx, "cdn")
if err != nil {
	return err
}
databaseURL := values["DATABASE_URL"]
defer databaseURL.Zeroize()

err = client.SetSecret(ctx, "cdn", "DATABASE_URL", secrets.Secret("postgres://new"))
```

## Security defaults

- `ServerURL` must use `https://` (`New` returns `ErrInsecureURL` otherwise).
- Bearer tokens are sent only in the `Authorization` header, never in the URL.
- Secret values are exposed as mutable `Secret` byte slices so callers can
  `Zeroize()` them after use.
- `Secret.String()` is redacted (`[secret]`); token and secret values are never
  included in errors or formatted output.

## License

MIT. See [LICENSE](LICENSE).
