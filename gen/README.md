# Fixture generator

`generate.py` deterministically creates the visible archive, fixed hidden findings, and fixed fresh-finding fixture. It is not copied into the task image.

Run it from `task/`:

    python3 gen/generate.py

The generator evaluates a posture-local whole-finding arbitration family. It enumerates own-repeat and peer-quorum readings, all 32 exploited surface scopes, internal behavior, both flag-gate orders, all six action precedence permutations, and every fallback flag scope. The complete family has 442,368 policy settings per posture. It repairs the public archive until every setting that fits a posture's visible decisions produces the same observable result on fixed, fresh, random audit, and exhaustive semantic audit findings. The semantic audit enumerates every flag set, target, one-to-five surface sequence, and severity order relevant to this policy family. It also rejects a single global policy, per-vector selectors, constants, and the naive default; checks every surface, flag set, vector count, output action, and all-related finding regime in visible data; and requires each nondefault policy axis to affect fixed hidden data.
