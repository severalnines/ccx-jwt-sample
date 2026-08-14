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

## Embedding CCX in an iframe

The demo page also shows the embedded flow: the `login (iframe)` button posts the same form to `/embed-ccx`, which creates and verifies the JWT exactly like `login-to-ccx`, but returns the login URL as JSON instead of redirecting. The page then sets that URL as the `src` of the `<iframe>` below the form — the way an integrator's portal would embed CCX.

The redirect flow is a top-level navigation, so the session cookie is always accepted. The iframe GET is a cross-site request instead, and three browser mechanisms must allow it: the CSP `frame-ancestors` of CCX, the `X-Frame-Options` header, and the cookie's `SameSite` attribute. See [Embedding CCX in an iframe](https://severalnines.github.io/ccx-docs/docs/admin/Customisation/JWT#embedding-ccx-in-an-iframe) in the CCX docs for the full story.

To test it against a local CCX (e.g. in docker-desktop k8s):

1. In the ccx chart values, in addition to the JWT key config above (requires CCX >= 1.58):

   ```yaml
   crossOrigins:
     - http://localhost:8088
   ccx:
     env:
       SESSION_COOKIE_SAMESITE: "none"
   ```

   `SESSION_COOKIE_SAMESITE: "none"` is for dev/testing only — in production, run CCX on a subdomain of the same registrable domain as the portal instead, so the cookie is same-site and needs no override (see the docs link above).

2. In the ccxdeps chart values, remove the `X-Frame-Options` header added by ingress-nginx:

   ```yaml
   ingress-nginx:
     controller:
       addHeaders:
         X-Frame-Options: null
   ```

   Then apply and restart the ingress-nginx controller (it does not watch this ConfigMap for changes):

   ```sh
   helm upgrade --install ccxdeps s9s/ccxdeps -n <namespace> -f ccxdeps-values.yaml
   kubectl -n <namespace> rollout restart daemonset ccxdeps-ingress-nginx-controller
   ```

3. If CCX uses a self-signed certificate, open the CCX URL directly in the browser once and accept the certificate — otherwise the iframe fails silently.

4. Run the app with `-insecure` as above, open http://localhost:8088, fill the form and press `login (iframe)`.

Note: only Chromium-based browsers block the cross-site cookie, so the `SESSION_COOKIE_SAMESITE` override is only needed there. Firefox partitions third-party cookies instead of blocking them, and the iframe works without it.
