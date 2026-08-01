# Finding triage task

A terminal-based benchmark task. An agent is given a labeled archive of triage decisions and
must reconstruct the router, then reproduce its decision for findings it has not seen.

## Layout

    instruction.md        what the agent is told to do
    task.toml             metadata, resources, timeouts
    environment/          the agent container and its input data
    solution/             reference solution
    tests/                automated verifier
    gen/                  fixture generator

## Running

Build the environment image, run the agent against `instruction.md`, then run `tests/test.sh`. The
verifier writes a pass or fail result and grades the produced output only.
