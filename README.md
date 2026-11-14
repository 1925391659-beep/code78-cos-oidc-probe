# OIDC claim verification

Two manually dispatched workflows verify GitHub-issued identity claims against GitHub's public JWKS. Each workflow uses a separate deployment environment and audience. The verifier reports selected claims only.

Run the offline checks with `node --test verify.test.mjs`.
