Finding Disposition Archive Format

`archive.txt` is a labeled archive. Each blank-line separated block describes one finding record and ends with its decision prefixed by `=> `. Program output never includes that prefix.

Each record has one posture line and one finding line:

    POSTURE=<W1|W2|W3>
    FINDING flags=<flag-list|-> target=<U1|U2|U3|U4|U5>

It also has one to five vector lines in arbitrary order:

    VECTOR <id> surface=<U1|U2|U3|U4|U5> severity=<positive-integer>

A record with n vector lines uses the ids `V1` through `Vn`, one per line, listed in arbitrary order. Vector severity values are unique within a record. Flags are a comma-separated set drawn from `exploited`, `internal`, and `unreachable`. Input ordering has no semantic effect.

The surface pairs `U1,U3`, `U1,U5`, and `U2,U4` are related. No other distinct surface pair is related.

A decision is exactly one of:

    PATCH <id>
    MITIGATE <id>
    AGGREGATE
    WATCH
    DISMISS

`PATCH` and `MITIGATE` must name a vector id from the same record. The router makes one whole-finding decision, not independent per-vector decisions.

The archive is the normative and complete specification: each output is fully determined by its record, and every posture behavior is recoverable from archived pairs alone. A reading that fits the archive but not the complete valid record range is not the router's policy.
