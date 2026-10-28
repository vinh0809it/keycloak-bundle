# Security policy

This bundle verifies the access tokens a Symfony firewall trusts, so a flaw in it can let a request
through as someone else. Please report one privately, not in a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/vinh0809it/keycloak-bundle/security/advisories/new).

Include what an attacker sends, what the firewall does with it, and the bundle, Symfony and
Keycloak versions. You will get an answer within 7 days. A confirmed issue is fixed in a release
and published as a GitHub security advisory, crediting you unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes while the bundle is on 0.x.

## Scope

In scope: anything that makes the `keycloak` authenticator accept a token it should refuse (a bad
signature, another issuer, another audience, an expired token), a dev token honoured outside
development, or a secret or token leaked by the client, the session cookies or the logs.

Out of scope: Keycloak itself and Symfony's own OIDC handler, which are reported to their own
projects, and `KeycloakStub`, which is a test tool.
