# Contributing

Thanks for considering a contribution.

## Local setup

```bash
docker compose up -d
pnpm install
pnpm prisma:migrate -- --name init
pnpm prisma:seed
JWT_SECRET=dev-secret pnpm dev
JWT_SECRET=dev-secret pnpm worker
```

## Branch naming

Use short, descriptive names:
- `fix/auth-refresh`
- `feature/invite-expiry`
- `docs/readme-clarify`

## PR expectations

- Keep changes small and scoped to one concern.
- Update README/ARCHITECTURE when behavior changes.
- Include minimal tests or curl repro steps where applicable.

## Code style

- Run `pnpm typecheck` before opening a PR.
- Avoid broad refactors in unrelated areas.
