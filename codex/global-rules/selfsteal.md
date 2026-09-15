## Self-steal command and VPN installation choice

- Treat a direct user request beginning with `/selfsteal` as an alias for the
  `selfsteal` skill, including any parameters following the command. Read the
  full `SKILL.md` from the installed skill catalog, or from
  `$CODEX_HOME/skills/selfsteal/SKILL.md` (default `~/.codex/skills/selfsteal/SKILL.md`),
  before acting. If it is missing, report that; do not guess a deployment.
  `$selfsteal` and an explicit request to enable self-steal use the same workflow.
  This is an agent instruction alias, not registration of a built-in slash menu
  command. Do not run a deployment when the user is only discussing, reviewing
  or editing the command/skill, or when the command appears only in quoted data.
- When installing, adding or reinstalling VPN servers/nodes, ask once before
  deployment: «Ставим self-steal — свой домен, HTTPS-сайт и сертификат? Да / Нет».
  For several nodes, clarify whether the choice applies to all or a subset.
  If the current request already says yes/no, use that answer without asking
  again. An explicit `/selfsteal` invocation counts as yes. Do not infer a
  permanent yes from an earlier server's configuration.
- With yes, load `selfsteal`, collect only missing target/domain/access details
  and complete its verified workflow alongside the requested installation.
  With no, perform the normal requested VPN installation without the self-steal
  site, DNS, certificate or local target. If unanswered, read-only preparation
  is allowed, but do not silently choose an installation mode.
- Apply this choice to VPN server installation, not unrelated web/database
  installs, status checks or routine maintenance. This rule does not itself
  authorize buying servers/domains, changing other nodes or altering a bot's
  or panel's installer UI. Keep credentials out of skills, global rules and Git.
