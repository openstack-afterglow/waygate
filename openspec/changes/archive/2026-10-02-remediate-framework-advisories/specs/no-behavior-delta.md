# No behavioral specification delta

This dependency-only change introduces no added, modified, removed or renamed product requirements. Existing `repository-workflow` and `ci-workflow` specifications remain authoritative; their required evidence, ownership, secret-handling, authorization, release and architecture-review boundaries are unchanged.

The implementation acceptance criteria are FastAPI `==0.136.3`, a service-extra Starlette `>=1.3.1` floor, root uv lock Starlette `1.3.1`, unrelated dependency selections preserved, and unchanged Waygate source/public contracts. Version selection outside the five documented advisory ranges is not runtime or production proof. Parent's completed isolated acceptance checks are recorded in `../tasks.md`; metadata compatibility and framework behavior risks are recorded in `../design.md`.

No delta is to be synchronized into the main specifications as a new API or Host policy. If Main's verification establishes a required contract/policy change, report it and obtain a revised design before implementing such a change.
