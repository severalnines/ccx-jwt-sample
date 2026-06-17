# ccx-jwt-sample

Demonstration of logging into CCX using a JWT. The app simulates an integrator's platform of webapp and server, and performs the actions to let the user get a CCX session. In reality, the user's details would all come from a database or IDP, but in this demo they can be directly typed into a form.

CCX must be pre-configured with a client-id and public key. Both `ccx-auth-service` (validates the JWT) and `ccx-user` (creates/updates the user) read `JWT_PUBLIC_KEY_ID` and `JWT_PUBLIC_KEY_PEM`, so the simplest place to set them in the helm chart is the global `ccx.env`, which propagates into every service via the shared configmap:

```yaml
ccx:
  env:
    JWT_PUBLIC_KEY_ID: "mycloud"
    JWT_PUBLIC_KEY_PEM: |
      -----BEGIN RSA PUBLIC KEY-----
      xxxx
      -----END RSA PUBLIC KEY-----
```

If the key is in PKIX (`-----BEGIN PUBLIC KEY-----`) form rather than PKCS#1, also set `JWT_PUBLIC_KEY_PKIX: "1"`.

The demo app will be configured with these too, e.g. these are the defaults:

```sh
$ go run . -ccx=https://ccx.s9s-dev.net/api/auth -cloud=mycloud -keyfile=key.pem
```

For dev against a CCX install with a self-signed cert, add `-insecure` to skip TLS verification when calling the CCX API:

```sh
$ go run . -ccx=https://ccx.s9s-dev.net/api/auth -cloud=mycloud -keyfile=key.pem -insecure
```

When the user information is provided with the web form, the app:

* creates a JWT using the user data and private key
* sends the JWT to CCX with a POST request (`login-to-ccx`)
* checks the response
* returns a redirect, so that the browser will fetch a CCX URL with the JWT.

The user recieves a CCX cookie in response, along with the CCX UI. That is, this redirect is both redirecting to the CCX UI and finishing the login process.

In a real situation, instead of showing a form, the integrator will likely set their version of the demo app's `login-to-ccx` into `FE_AUTH_REDIRECT_URL`. The process for loading CCX will be just to send the user straight to CCX, and CCX will redirect back to the integrator to trigger an automatic login, ending with the user being send back to CCX.
