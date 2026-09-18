# Datazap Partner API

Integration guides and client code for the [Datazap](https://datazap.me) Partner API, which lets your app upload data
logs straight into a user's Datazap account after they approve it once on a consent screen.

The API is OAuth 2.0 Authorization Code with PKCE plus three JSON/multipart endpoints: list projects, upload logs, and an
optional plan and usage call. The language guides below each contain the complete flow, a reviewed client, and the two
integration patterns we recommend (a *Send to Datazap* action, and opt-in auto-upload).

## Implementations

| Language | Guide |
|---|---|
| C# / .NET 8 (MAUI, WPF, WinForms, console) | [`csharp/`](csharp/) |

More languages will be added here. If you are integrating in something else, the C# guide still documents the API
end to end; only the code is language-specific.

## Getting set up

You send us the redirect URIs your app will use and we send back a `client_id`. Mobile and desktop apps are registered
as public clients and authenticate with PKCE, so no client secret is issued. Details are in the guide for your language,
under *Getting set up* and *Going live*.

Questions or a stuck integration: **support@datazap.me**.

## Layout

```
csharp/    C# guide (README.md) and its code as plain files under code/
docs/      PDF versions of the guides
```

## License

MIT. Copy whatever is useful.
