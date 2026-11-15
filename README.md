# OAuth2-WebActions Server

Bridge the gap between command-line and web interfaces with OAuth2-WebActions (O2WA).

This tool transforms CLI workflows into web actions while leveraging the security of OAuth2.0 and OIDC.

## Features

1. **Your CLI on the Web**: Convert command-line tasks into web actions, making powerful commands accessible to non-tech-savvy users.
  
2. **Robust Security**: OAuth2.0 and OIDC integration ensure the secure execution of web-based commands.

3. **Dynamic Endpoints**: The server adapts web endpoints to commands via a YAML configuration, ensuring flexibility without altering the core code.

4. **Interactive Feedback**: Get HTML feedback for every command executed through the web, enhancing the user experience.

## Why Choose O2WA?

1. **Simplify for Users**: Make intricate tasks user-friendly by transitioning them from the CLI to the web.

2. **Unified Command Management**: Update commands centrally, maintaining consistency for all users.

3. **Safety First**: OAuth2 and OIDC-backed authentication ensure the safety of every command.

4. **Scalable**: Seamlessly incorporate new CLI tasks into the web interface via dynamic endpoints.

Consider O2WA if you're looking to expand your CLI operations to a wider audience securely and efficiently.

---

## Quickstart:

For those who like a straightforward setup without the need for containerization, here's a guide to quickly get a O2WA server operational:

### Step 1: Install `o2wa`

You have two options:

**Option A: From GitHub Releases**

1. Visit the [GitHub releases page](https://github.com/miguelangel-nubla/o2wa/releases).
2. Depending on your operating system and architecture, download the appropriate release asset. For instance:
   - For macOS with arm64: `O2WA_Darwin_arm64.tar.gz`
   - For Linux with x86_64: `O2WA_Linux_x86_64.tar.gz`
   ... and so on.
3. Extract the downloaded file.
4. Move the binary to a location in your system's `$PATH`, or you can execute it directly from the extracted folder.

**Option B: Using Go**

If you have Go installed, you can directly install the package:

```bash
go install github.com/miguelangel-nubla/o2wa@latest
```

Ensure your `$GOPATH/bin` directory is in your `$PATH` to run the installed binary from anywhere.

### Step 2: Set Up Configuration

In the directory where `o2wa` is installed or your working directory, you'll find a sample `config.example.yaml` configuration file. Tailor this file to your environment:

Ensure you update the OAuth2 endpoint URLs, client credentials, and define any custom commands as needed.

Use the provided /public endpoint that runs `echo Hello world!` as a starting point.

The configuration is checked at startup: an unknown or misspelled key stops o2wa instead of being ignored (a
misspelled `requiredGroups` would otherwise leave an endpoint open to every logged-in user). An endpoint that is not
`public` and has no `requiredGroups` is open to every user the identity provider lets log in.

### Step 3: Launch `o2wa`

With everything configured, you can start `o2wa`:

```bash
o2wa
```

### Step 4: Access the Web Interface

Open a browser and navigate to the `o2wa` web interface:

```
http://localhost:8080  # Make sure to adjust the port if you've modified it in config.yaml
```

Then, follow the on-screen guidance to authenticate and execute your defined commands.

---

## Endpoints

Each endpoint serves a page on GET (`htmlFile`, or a built-in page that asks for confirmation and shows the output)
and runs its `command` on POST. Command arguments and pages are Go templates with `.GET`, `.POST`, `.AuthClaims`
(nil on a public endpoint without a login), `.HTTPRequestHeaders` and `.CSRFToken`; pages are rendered with
`html/template`, so request values end up escaped, not as markup. The command runs directly, never through a shell.

Request values are untrusted input to the command:

- A missing value renders as `<no value>`, never as an empty argument, so a script that defaults an empty argument
  cannot be steered into its default. Reject `<no value>` in the script.
- A value may start with `-`: put it after `--`, or validate it, so it cannot become an option.

A POST needs the session's CSRF token: in the `X-CSRF-Token` header (fetch from the page's script), or in a
`csrfToken` form field, so a plain HTML form can post and let the browser handle the response itself (open a
downloaded file, install a profile):

```html
<form method="post" action="/get-file"><input type="hidden" name="csrfToken" value="{{.CSRFToken}}">
  <button>Download</button></form>
```

By default the output streams as NDJSON lines (`{"timestamp","source":"stdout"|"stderr","text"}`). With
`binaryOutput: true`, stdout is the response body: `contentType` sets its media type (default
`application/octet-stream`) and `fileName` makes it a download with that name. stderr is logged. A command that
fails before printing anything answers with a plain 500 error, not with a file. Responses are sent with
`Cache-Control: no-store`.

An endpoint's `timeout` (a Go duration such as `60s`) kills a command that runs longer; without it a command may
run forever. The command is not tied to the request: it finishes even if the browser goes away.

Pages and `/values` get the request headers except `Cookie` and `Authorization`. Every response forbids framing.

A logged-in user without the endpoint's groups gets 403. `/logout` ends the o2wa session only, not the identity
provider's.

## Sessions and group changes

A login lasts up to 24 hours, but o2wa only trusts the user's groups until the ID token expires. After that it renews the
tokens with the refresh token and reads the groups again, so removing a user from a group (or expiring their account)
takes effect at the next ID token expiry. If the provider refuses the refresh, the user logs in again.

o2wa waits for the identity provider at startup, retrying discovery, so it can start before the provider does.

Sessions live in memory, so a restart logs everyone out; the next page load logs in again (silently, when the
provider still has a session). A login interrupted that way, started in another browser, or a reloaded callback URL
does not end in an error: o2wa takes the user to the page they wanted, through one new login if needed.

The session cookie is `SameSite=Strict`: a link from another site opens o2wa without the session, so it cannot run a
page's command on load as the user. This needs the identity provider on the same site (registrable domain) as o2wa;
otherwise the redirect back to the callback arrives without the cookie and the login cannot finish.

## Docker Deployment

Sample config.example.yaml is provided in the repository. Deploy with:

```bash
docker run \
    -p 8080:8080 \
    -v $PWD/config.yaml:/config.yaml \
    ghcr.io/miguelangel-nubla/o2wa:latest
```

### Initialization Script for Custom Tools

In scenarios where `o2wa`'s custom commands require special tools or setups, you can introduce an initialization script that runs before the main program.

1. Prepare your initialization script. For instance, name it `custom-init.sh`.
   
2. Launch the Docker container, mounting your script and setting `INIT_SCRIPT_PATH``:
    ```bash
    docker run \
        -p 8080:8080 \
        -v $PWD/config.yaml:/config.yaml \
        -v /path/to/your/custom-init.sh:/custom-init.sh \
        -e INIT_SCRIPT_PATH=/custom-init.sh \
        ghcr.io/miguelangel-nubla/o2wa
    ```

Your script will execute before `o2wa`, ensuring the necessary tools or configurations are in place.

### Custom CA Certificates

`o2wa` might interact with services using certificates from a private/internal CA. For smooth, secure interactions, trust these certificates.

For Docker deployments, mount your CA certificates (PEM, as `.crt` or `.pem` files) at `/trusted-ca-certs`:

```bash
docker run \
    -p 8080:8080 \
    -v $PWD/config.yaml:/config.yaml \
    -v /path/to/your/ca/certs:/trusted-ca-certs \
    ghcr.io/miguelangel-nubla/o2wa
```

## Contributing

Enhance O2WA through documentation improvements, added features, or issue resolutions. Your contributions are valued!