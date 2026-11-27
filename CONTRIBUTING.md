# Contributing

Thank you for helping improve the middleware.

## Ground rules

- Keep the runtime dependency surface limited to the thirteen security packages already declared.
- Do not add Express, Fastify, Koa, TypeScript, or test framework runtime dependencies.
- Use `node:test` for tests.
- Test security behavior through real HTTP requests whenever the behavior crosses a network boundary.
- Keep error responses small and avoid reflecting attacker-controlled values.
- Do not commit secrets, tokens, private keys, or personal data.

## Local verification

```sh
npm ci
npm run verify
```

`npm run verify` runs the attack test suite, checks both module entry points, validates the type surface, and syntax checks all examples.

## Pull requests

Include:

1. The security problem or usability problem being solved.
2. A regression test for behavior changes.
3. Notes about compatibility and threat model impact.
4. Updated documentation when public behavior changes.

Small focused pull requests are easiest to review.
