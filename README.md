# K.O.D.A.

**Kinetic Operative Defense Agent** — an open-source security specialist agent.

Built by [Vektra Industries](https://vektra.industries).

K.O.D.A. is a harness for running a security-focused AI agent against your code,
hosts, and infrastructure. It ships with a tool-first execution model, a grounding
verifier that rejects fabricated claims, and a semantic router that escalates
action-intent prompts into real tool calls before the model can improvise.

## Why another agent

Most agent frameworks are general-purpose. Security work isn't. When a user asks
"is my project safe?" a general-purpose agent will often write a confident-looking
report from thin air — fake CVEs, fake file paths, fake line numbers. K.O.D.A.
treats every security claim as ungrounded until a tool has produced evidence for
it.

## Status

Early. The harness skeleton is in place; provider adapters, tool bundles, and
the grounding verifier are being wired up. Not production-ready. Expect breaking
changes.

## License

MIT. See [LICENSE](./LICENSE).

Architectural credit: this codebase is an independent reimplementation
inspired by the open-source harness patterns of
[Nous Research's Hermes](https://github.com/NousResearch/hermes-agent) (MIT)
and [OpenClaw](https://www.npmjs.com/package/openclaw). No code was copied; the
patterns were analyzed and rewritten from scratch for the security domain.
