import sys


PAIRS = {
    frozenset(("U1", "U3")),
    frozenset(("U1", "U5")),
    frozenset(("U2", "U4")),
}

RULES = {
    "W1": ("one", "one", "early", "early", "off", "none", "none", ("exploited", "internal"), ("MITIGATE", "PATCH", "AGGREGATE"), "none"),
    "W2": ("repeat", "two_alerts", "late", "early", "off", "U4,U5", "none", ("exploited", "internal"), ("PATCH", "MITIGATE", "AGGREGATE"), "exploited,internal,unreachable"),
    "W3": ("repeat", "two_sources", "late", "late", "all_peer", "U4,U5", "ifcand", ("exploited", "internal"), ("AGGREGATE", "PATCH", "MITIGATE"), "exploited,internal,unreachable"),
}


def fields(text):
    return dict(item.split("=", 1) for item in text.split())


def parse(text):
    posture = None
    flags = set()
    target = None
    alerts = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("POSTURE="):
            posture = line.split("=", 1)[1]
        elif line.startswith("FINDING "):
            row = fields(line[8:])
            flags = set() if row["flags"] == "-" else set(row["flags"].split(","))
            target = row["target"]
        elif line.startswith("VECTOR "):
            parts = line[7:].split()
            row = fields(" ".join(parts[1:]))
            alerts.append({"id": parts[0], "source": row["surface"], "at": int(row["severity"])})
    return posture, flags, target, alerts


def related(left, right):
    return frozenset((left, right)) in PAIRS


def pick(alerts, direction):
    ordered = sorted(alerts, key=lambda item: (item["at"], item["id"]))
    return ordered[0] if direction == "early" else ordered[-1]


def resolve(rule, flags, target, alerts):
    own_support, related_support, own_pick, related_pick, collapse_mode, exploited_scope, internal_mode, gates, order, fallback_scope = rule
    own = [item for item in alerts if item["source"] == target]
    rel = [item for item in alerts if related(target, item["source"])]
    vectors = {}
    if own and (own_support == "one" or len(own) >= 2):
        vectors["PATCH"] = pick(own, own_pick)["id"]
    if rel and (related_support == "one" or (related_support == "two_alerts" and len(rel) >= 2) or (related_support == "two_sources" and len({item["source"] for item in rel}) >= 2)):
        vectors["MITIGATE"] = pick(rel, related_pick)["id"]
    if collapse_mode == "all_peer" and alerts and all(related(target, item["source"]) for item in alerts):
        vectors["AGGREGATE"] = None
    for gate in gates:
        if gate == "exploited" and "exploited" in flags and exploited_scope != "none" and target in exploited_scope.split(","):
            return "WATCH"
        if gate == "internal" and "internal" in flags and (internal_mode == "always" or (internal_mode == "ifcand" and vectors)):
            return "AGGREGATE"
    for kind in order:
        if kind in vectors:
            return kind if vectors[kind] is None else kind + " " + vectors[kind]
    if fallback_scope != "none" and any(flag in fallback_scope.split(",") for flag in flags):
        return "WATCH"
    return "DISMISS"


def classify(text):
    posture, flags, target, alerts = parse(text)
    return resolve(RULES[posture], flags, target, alerts)


if __name__ == "__main__":
    print(classify(sys.stdin.read()))
