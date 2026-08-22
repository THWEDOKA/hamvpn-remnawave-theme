# HAMVPN Infrastructure UI

## Direction

Operator-first control surface for emergency infrastructure work. The interface prioritizes dependency visibility, explicit confirmation, verification, and rollback over raw terminal output.

## Tokens

- Canvas: `#09060d`
- Panel: `rgba(19, 14, 27, .88)`
- Primary text: `#f5f1fa`
- Muted text: `#91899b`
- Violet action: `#c4a4ff`
- Success: `#68e6ba`
- Pending: `#f2bd70`
- Danger: `#ff7d94`
- Border: `rgba(226, 211, 255, .11)`
- Grid: 4 px base, 16 px panel radius, 9–12 px control radius
- Typography: Montserrat with system fallback; monospace only for IP, port, UUID, and stage labels

## Components

- Sidebar navigation with a persistent exact-version lock indicator
- Four-stage operation pipeline: preflight, snapshot, apply, verify
- Impact plan with node root and indented host/profile dependencies
- Confirmation field requiring exact resource name before mutation
- Status chips: green completed, amber pending, red rollback/error
- Audit rows never expose tokens, credentials, private keys, or configuration snapshots
- DNS impact rows show exact hostname and old → new IP in monospace, with DNS-only and TTL as explicit policy states

## Behavior

- Planning and preflight do not mutate infrastructure
- Mutation buttons enter a visible busy state and cannot be double-submitted
- Existing node installations are never overwritten automatically
- Hysteria domain changes are blocked before mutation unless the exact Cloudflare record is verified
- Mobile navigation moves to a four-button bottom rail
