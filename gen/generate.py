#!/usr/bin/env python3
from __future__ import annotations

import itertools
import json
import random
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
TASK = HERE.parent
DATA = TASK / "environment" / "data"
HIDDEN = TASK / "tests" / "data"
FRESH_PATH = TASK / "tests" / "fresh_cases.py"
SEED = 33072026
R = random.Random(SEED)

SOURCES = ("U1", "U2", "U3", "U4", "U5")
FLAGS = ("exploited", "internal", "unreachable")
MODES = ("W1", "W2", "W3")
PAIRS = {
    frozenset(("U1", "U3")),
    frozenset(("U1", "U5")),
    frozenset(("U2", "U4")),
}

TRUE = {
    "W1": ("one", "one", "early", "early", "off", "none", "none", ("exploited", "internal"), ("MITIGATE", "PATCH", "AGGREGATE"), "none"),
    "W2": ("repeat", "two_alerts", "late", "early", "off", "U4,U5", "none", ("exploited", "internal"), ("PATCH", "MITIGATE", "AGGREGATE"), "exploited,internal,unreachable"),
    "W3": ("repeat", "two_sources", "late", "late", "all_peer", "U4,U5", "ifcand", ("exploited", "internal"), ("AGGREGATE", "PATCH", "MITIGATE"), "exploited,internal,unreachable"),
}
NAIVE = ("one", "one", "early", "early", "off", "none", "none", ("exploited", "internal"), ("PATCH", "MITIGATE", "AGGREGATE"), "none")
PATCH_SUPPORT = ("one", "repeat")
MITIGATE_SUPPORT = ("one", "two_alerts", "two_sources")
PICKS = ("early", "late")
AGGREGATE = ("off", "all_peer")
CANARY = ("none", "ifcand", "always")
GATES = tuple(itertools.permutations(("exploited", "internal")))
ORDERS = tuple(itertools.permutations(("PATCH", "MITIGATE", "AGGREGATE")))
FALLBACKS = ("none",) + tuple(
    ",".join(items)
    for size in range(1, len(FLAGS) + 1)
    for items in itertools.combinations(FLAGS, size)
)
MASKS = ("none",) + tuple(
    ",".join(items)
    for size in range(1, len(SOURCES) + 1)
    for items in itertools.combinations(SOURCES, size)
)
BASE_MASKS = ("none", "U4,U5")
BASE_FALLBACKS = ("none", "exploited,internal,unreachable")
FAMILY = tuple(itertools.product(PATCH_SUPPORT, MITIGATE_SUPPORT, PICKS, PICKS, AGGREGATE, BASE_MASKS, CANARY, GATES, ORDERS, BASE_FALLBACKS))
ALL_FAMILY = tuple(itertools.product(PATCH_SUPPORT, MITIGATE_SUPPORT, PICKS, PICKS, AGGREGATE, MASKS, CANARY, GATES, ORDERS, FALLBACKS))
FIDX = {rule: index for index, rule in enumerate(FAMILY)}

LAB_MIN = 28
HELD_MIN = 8
FRESH_PER_MODE = 16
POOL_N = 1600
FRESH_POOL_N = 900


def related(left: str, right: str) -> bool:
    return frozenset((left, right)) in PAIRS


def peers(source: str) -> tuple[str, ...]:
    return tuple(other for other in SOURCES if related(source, other))


def choose(alerts: list[dict], direction: str) -> dict:
    ordered = sorted(alerts, key=lambda item: (item["at"], item["id"]))
    return ordered[0] if direction == "early" else ordered[-1]


def resolve(rule, flags: tuple[str, ...], target: str, alerts: tuple[dict, ...]) -> str:
    own_support, related_support, own_pick, related_pick, collapse_mode, exploited_scope, internal_mode, gates, order, fallback_scope = rule
    own = [item for item in alerts if item["source"] == target]
    rel = [item for item in alerts if related(target, item["source"])]
    vectors = {}
    if own and (own_support == "one" or len(own) >= 2):
        vectors["PATCH"] = choose(own, own_pick)["id"]
    if rel and (related_support == "one" or (related_support == "two_alerts" and len(rel) >= 2) or (related_support == "two_sources" and len({item["source"] for item in rel}) >= 2)):
        vectors["MITIGATE"] = choose(rel, related_pick)["id"]
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


def label(record: dict) -> str:
    return resolve(TRUE[record["mode"]], record["flags"], record["target"], record["alerts"])


def dv(rule, record: dict) -> str:
    return resolve(rule, record["flags"], record["target"], record["alerts"])


def mk(mode: str, flags: list[str], target: str, sources: list[str]) -> dict:
    moments = R.sample(range(3, 260), len(sources))
    alerts = tuple(
        {"id": "V%d" % (index + 1), "source": source, "at": moment}
        for index, (source, moment) in enumerate(zip(sources, moments))
    )
    return {"mode": mode, "flags": tuple(sorted(set(flags))), "target": target, "alerts": alerts}


def rflags() -> list[str]:
    return [flag for flag in FLAGS if R.random() < 0.31]


def rich(mode: str) -> dict:
    return mk(mode, rflags(), R.choice(SOURCES), [R.choice(SOURCES) for _ in range(R.randint(3, 5))])


def single_peer(mode: str) -> dict:
    target = R.choice(SOURCES)
    return mk(mode, rflags(), target, [R.choice(peers(target))])


def pair_window(mode: str) -> dict:
    target = R.choice(SOURCES)
    return mk(mode, rflags(), target, [target, R.choice(peers(target))])


def r2_boundary(mode: str) -> dict:
    if mode == "W2":
        return mk(mode, ["exploited"], "U3", ["U1"])
    return single_peer(mode)


def r1_own_pick_boundary(mode: str) -> dict:
    if mode == "W1":
        return mk(mode, [], "U1", ["U1", "U1"])
    return own_conflict(mode)


def all_peer(mode: str) -> dict:
    target = R.choice(SOURCES)
    choices = peers(target)
    return mk(mode, [flag for flag in rflags() if flag != "exploited"], target, [R.choice(choices) for _ in range(R.randint(3, 5))])


def all_peer_small(mode: str) -> dict:
    target = R.choice(SOURCES)
    choices = peers(target)
    count = R.randint(1, 2)
    sources = list(choices) if count == 2 and len(choices) >= 2 else [R.choice(choices) for _ in range(count)]
    return mk(mode, [flag for flag in rflags() if flag not in ("exploited", "internal")], target, sources)


def own_only_one(mode: str) -> dict:
    target = R.choice(SOURCES)
    return mk(mode, [], target, [target])


def own_only_two(mode: str) -> dict:
    target = R.choice(SOURCES)
    return mk(mode, [], target, [target, target])


def own_count(record: dict) -> int:
    return sum(1 for item in record["alerts"] if item["source"] == record["target"])


def peer_count(record: dict) -> int:
    return sum(1 for item in record["alerts"] if related(record["target"], item["source"]))


def own_conflict(mode: str) -> dict:
    target = R.choice(SOURCES)
    sources = [target, target] + [R.choice(SOURCES) for _ in range(R.randint(1, 3))]
    R.shuffle(sources)
    return mk(mode, rflags(), target, sources)


def related_conflict(mode: str) -> dict:
    target = R.choice(SOURCES)
    choices = peers(target)
    sources = [R.choice(choices), R.choice(choices)] + [R.choice(SOURCES) for _ in range(R.randint(1, 3))]
    R.shuffle(sources)
    return mk(mode, rflags(), target, sources)


def related_diverse(mode: str) -> dict:
    sources = ["U3", "U5"] + [R.choice(SOURCES) for _ in range(R.randint(1, 3))]
    R.shuffle(sources)
    return mk(mode, rflags(), "U1", sources)


def own_related(mode: str) -> dict:
    target = R.choice(SOURCES)
    sources = [target, R.choice(peers(target))] + [R.choice(SOURCES) for _ in range(R.randint(1, 3))]
    R.shuffle(sources)
    return mk(mode, rflags(), target, sources)


def gate_scope_witness(mode: str) -> dict:
    target = R.choice(("U1", "U2", "U3"))
    return mk(mode, ["exploited"], target, [target, target])


def precedence_witness(mode: str) -> dict:
    target = R.choice(SOURCES)
    return mk(mode, [], target, [target, R.choice(peers(target))])


def exploited_record(mode: str) -> dict:
    target = R.choice(SOURCES)
    trigger = R.choice([target] + list(peers(target)))
    sources = [trigger] + [R.choice(SOURCES) for _ in range(R.randint(2, 4))]
    R.shuffle(sources)
    return mk(mode, ["exploited"] + (["unreachable"] if R.random() < 0.4 else []), target, sources)


def internal_record(mode: str) -> dict:
    record = R.choice((own_conflict, related_conflict, own_related))(mode)
    flags = [flag for flag in record["flags"] if flag != "exploited"]
    if "internal" not in flags:
        flags.append("internal")
    return {"mode": record["mode"], "flags": tuple(sorted(flags)), "target": record["target"], "alerts": record["alerts"]}


def internal_without_vector(mode: str) -> dict:
    target = R.choice(SOURCES)
    blocked = set((target,)) | set(peers(target))
    choices = [source for source in SOURCES if source not in blocked]
    return mk(mode, ["internal"] + (["unreachable"] if R.random() < 0.4 else []), target, [R.choice(choices) for _ in range(R.randint(3, 5))])


def no_trigger(mode: str) -> dict:
    target = R.choice(SOURCES)
    blocked = set((target,)) | set(peers(target))
    choices = [source for source in SOURCES if source not in blocked]
    return mk(mode, rflags(), target, [R.choice(choices) for _ in range(R.randint(3, 5))])


BUILDERS = (rich, rich, single_peer, pair_window, r1_own_pick_boundary, r1_own_pick_boundary, r2_boundary, r2_boundary, all_peer, all_peer_small, all_peer_small, own_only_one, own_only_two, own_conflict, related_conflict, related_diverse, own_related, gate_scope_witness, gate_scope_witness, precedence_witness, precedence_witness, exploited_record, exploited_record, internal_record, internal_without_vector, no_trigger)


def key(record: dict):
    return (
        record["mode"],
        record["flags"],
        record["target"],
        tuple((item["id"], item["source"], item["at"]) for item in record["alerts"]),
    )


def seed_for(record: dict) -> int:
    text = "|".join((record["mode"], ",".join(record["flags"]), record["target"]))
    text += "|" + "|".join("%s:%s:%d" % (item["id"], item["source"], item["at"]) for item in record["alerts"])
    return sum((index + 1) * ord(char) for index, char in enumerate(text))


def serialize(record: dict, with_value: str | None = None) -> str:
    lines = ["POSTURE=" + record["mode"], "FINDING flags=%s target=%s" % (",".join(record["flags"]) if record["flags"] else "-", record["target"])]
    body = ["VECTOR %s surface=%s severity=%d" % (item["id"], item["source"], item["at"]) for item in record["alerts"]]
    random.Random(seed_for(record)).shuffle(body)
    lines.extend(body)
    if with_value is not None:
        lines.append("=> " + with_value)
    return "\n".join(lines)


def pool(mode: str, size: int) -> list[dict]:
    records = []
    seen = set()
    attempts = 0
    while len(records) < size and attempts < size * 80:
        attempts += 1
        record = R.choice(BUILDERS)(mode)
        signature = key(record)
        if signature not in seen:
            seen.add(signature)
            records.append(record)
    assert len(records) == size, (mode, len(records), size)
    return records


def changed_axis(rule, axis: int):
    patched = list(rule)
    patched[axis] = NAIVE[axis]
    return tuple(patched)


def build_mode(mode: str):
    records = pool(mode, POOL_N)
    rows = [[dv(rule, record) for rule in FAMILY] for record in records]
    labels = [label(record) for record in records]
    true_index = FIDX[TRUE[mode]]
    naive_index = FIDX[NAIVE]
    assert all(row[true_index] == expected for row, expected in zip(rows, labels))

    def refutes(rule_index: int, record_index: int) -> bool:
        return rows[record_index][rule_index] != labels[record_index]

    def naive_bad(record_index: int) -> bool:
        return rows[record_index][naive_index] != labels[record_index]

    need = [index for index in range(len(FAMILY)) if index != true_index and any(refutes(index, row) for row in range(len(records)))]
    counts = {index: 0 for index in need}
    selected = []
    order = list(range(len(records)))
    R.shuffle(order)
    while any(counts[index] == 0 for index in need):
        best_index = None
        best_count = -1
        for record_index in order:
            if record_index in selected:
                continue
            current = sum(1 for rule_index in need if counts[rule_index] == 0 and refutes(rule_index, record_index))
            if current > best_count:
                best_index = record_index
                best_count = current
        assert best_index is not None and best_count > 0, (mode, "base vector pool")
        selected.append(best_index)
        for rule_index in need:
            if refutes(rule_index, best_index):
                counts[rule_index] += 1

    seen_actions = set()
    for record_index in order:
        action = labels[record_index].split()[0]
        if action not in seen_actions:
            seen_actions.add(action)
            if record_index not in selected:
                selected.append(record_index)
    for record_index in order:
        if len(selected) >= LAB_MIN:
            break
        if record_index not in selected and not naive_bad(record_index):
            selected.append(record_index)
    for record_index in order:
        if len(selected) >= LAB_MIN:
            break
        if record_index not in selected:
            selected.append(record_index)

    held = []
    for axis in range(len(TRUE[mode])):
        if TRUE[mode][axis] == NAIVE[axis]:
            continue
        vector = changed_axis(TRUE[mode], axis)
        for record_index in order:
            if record_index not in selected and record_index not in held and dv(vector, records[record_index]) != labels[record_index]:
                held.append(record_index)
                break
    for record_index in order:
        if len(held) >= HELD_MIN:
            break
        if record_index not in selected and record_index not in held and naive_bad(record_index):
            held.append(record_index)
    for record_index in order:
        if len(held) >= HELD_MIN:
            break
        if record_index not in selected and record_index not in held:
            held.append(record_index)
    assert len(held) >= HELD_MIN, (mode, len(held))

    attempts = 0
    while True:
        attempts += 1
        assert attempts < 4000, (mode, "base repair")
        bad = None
        for rule_index, rule in enumerate(FAMILY):
            if rule_index == true_index or any(refutes(rule_index, record_index) for record_index in selected):
                continue
            if any(refutes(rule_index, record_index) for record_index in held):
                bad = rule_index
                break
        if bad is None:
            break
        found = next((record_index for record_index in order if record_index not in selected and record_index not in held and refutes(bad, record_index)), None)
        assert found is not None, (mode, "unrefuted base", FAMILY[bad])
        selected.append(found)

    attempts = 0
    while True:
        attempts += 1
        assert attempts < 4000, (mode, "scope repair")
        bad = None
        for mask in MASKS:
            if mask == TRUE[mode][5]:
                continue
            vector = list(TRUE[mode])
            vector[5] = mask
            vector = tuple(vector)
            if all(dv(vector, records[index]) == labels[index] for index in selected) and any(dv(vector, records[index]) != labels[index] for index in held):
                bad = vector
                break
        if bad is None:
            break
        found = next((index for index in order if index not in selected and index not in held and dv(bad, records[index]) != labels[index]), None)
        assert found is not None, (mode, "unrefuted scope", bad)
        selected.append(found)

    return [records[index] for index in selected], [records[index] for index in held], records


def choose_fresh(mode: str, used: set) -> list[dict]:
    records = pool(mode, FRESH_POOL_N)
    eligible = [record for record in records if key(record) not in used]
    vectors = [record for record in eligible if dv(NAIVE, record) != label(record)]
    R.shuffle(vectors)
    selected = []
    if mode == "W1":
        found = next((record for record in eligible if r1_own_pick_record(record)), None)
        assert found is not None, "fresh own-pick boundary missing"
        selected.append(found)
    if mode == "W2":
        found = next((record for record in eligible if r2_boundary_record(record)), None)
        assert found is not None, "fresh boundary missing"
        selected.append(found)
    actions = ("PATCH", "MITIGATE", "AGGREGATE", "WATCH", "DISMISS")
    for action in actions:
        found = next((record for record in vectors if record not in selected and label(record).split()[0] == action), None)
        if found is not None:
            selected.append(found)
    for record in vectors:
        if len(selected) >= FRESH_PER_MODE:
            break
        if record not in selected:
            selected.append(record)
    assert len(selected) == FRESH_PER_MODE, (mode, len(selected))
    return selected


def repair_full(mode: str, labeled: list[dict], challenge: list[dict], vectors: list[dict]) -> None:
    attempts = 0
    excluded = {key(record) for record in challenge}
    while True:
        attempts += 1
        assert attempts < 4000, (mode, "full repair")
        bad = None
        for rule in ALL_FAMILY:
            if all(dv(rule, record) == label(record) for record in labeled) and any(dv(rule, record) != label(record) for record in challenge):
                bad = rule
                break
        if bad is None:
            return
        found = next((record for record in vectors if key(record) not in excluded and key(record) not in {key(item) for item in labeled} and dv(bad, record) != label(record)), None)
        assert found is not None, (mode, "full refuter", bad)
        labeled.append(found)


def ensure(labeled: list[dict], held: list[dict], vectors: list[dict], predicate) -> None:
    if any(predicate(record) for record in labeled):
        return
    used = {key(record) for record in labeled + held}
    found = next((record for record in vectors if key(record) not in used and predicate(record)), None)
    assert found is not None, "coverage vector missing"
    labeled.append(found)


def ensure_held(labeled: list[dict], held: list[dict], vectors: list[dict], predicate) -> None:
    if any(predicate(record) for record in held):
        return
    used = {key(record) for record in labeled + held}
    found = next((record for record in vectors if key(record) not in used and predicate(record)), None)
    assert found is not None, "held coverage vector missing"
    held.append(found)


def action(record: dict) -> str:
    return label(record).split()[0]


def r2_boundary_record(record: dict) -> bool:
    return record["mode"] == "W2" and record["flags"] == ("exploited",) and record["target"] == "U3" and len(record["alerts"]) == 1 and record["alerts"][0]["source"] == "U1"


def r1_own_pick_record(record: dict) -> bool:
    return record["mode"] == "W1" and not record["flags"] and record["target"] == "U1" and len(record["alerts"]) == 2 and all(item["source"] == "U1" for item in record["alerts"])


def check_defaults(mode: str, labeled: list[dict]) -> None:
    assert any(dv(NAIVE, record) != label(record) for record in labeled), (mode, "naive")
    for axis in range(len(TRUE[mode])):
        if TRUE[mode][axis] == NAIVE[axis]:
            continue
        vector = list(NAIVE)
        vector[axis] = TRUE[mode][axis]
        vector = tuple(vector)
        if vector != TRUE[mode]:
            assert any(dv(vector, record) != label(record) for record in labeled), (mode, "patch", axis)


def check_held_axes(mode: str, held: list[dict]) -> None:
    for axis in range(len(TRUE[mode])):
        if TRUE[mode][axis] == NAIVE[axis]:
            continue
        vector = changed_axis(TRUE[mode], axis)
        assert any(dv(vector, record) != label(record) for record in held), (mode, "held axis", axis)


def check_wide(mode: str, labeled: list[dict], challenge: list[dict]) -> int:
    survivors = 0
    for rule in ALL_FAMILY:
        if all(dv(rule, record) == label(record) for record in labeled):
            survivors += 1
            assert all(dv(rule, record) == label(record) for record in challenge), (mode, "undiscoverable", rule)
    return survivors


def check_r2_boundary(labeled: list[dict], held: list[dict], fresh: list[dict]) -> None:
    vector = list(TRUE["W2"])
    vector[4] = "all_peer"
    vector = tuple(vector)
    assert any(r2_boundary_record(record) and dv(vector, record) != label(record) for record in labeled)
    assert any(r2_boundary_record(record) and dv(vector, record) != label(record) for record in held)
    assert any(r2_boundary_record(record) and dv(vector, record) != label(record) for record in fresh)


def check_r1_own_pick_boundary(labeled: list[dict], held: list[dict], fresh: list[dict]) -> None:
    vector = list(TRUE["W1"])
    vector[2] = "late"
    vector = tuple(vector)
    assert any(r1_own_pick_record(record) and dv(vector, record) != label(record) for record in labeled)
    assert any(r1_own_pick_record(record) and dv(vector, record) != label(record) for record in held)
    assert any(r1_own_pick_record(record) and dv(vector, record) != label(record) for record in fresh)


def one_axis_rules(mode: str, labeled: list[dict]) -> list[tuple]:
    true = TRUE[mode]
    rules = []
    for axis in range(len(true)):
        for value in sorted({rule[axis] for rule in ALL_FAMILY}):
            if value == true[axis]:
                continue
            vector = tuple(true[:axis] + (value,) + true[axis + 1:])
            if any(dv(vector, record) != label(record) for record in labeled):
                rules.append(vector)
    return rules


def cover_one_axis_rules(mode: str, labeled: list[dict], suite: list[dict], vectors: list[dict], blocked: list[dict]) -> None:
    remaining = [rule for rule in one_axis_rules(mode, labeled) if not any(dv(rule, record) != label(record) for record in suite)]
    used = {key(record) for record in blocked}
    while remaining:
        best = None
        best_score = 0
        for record in vectors:
            if key(record) in used:
                continue
            score = sum(dv(rule, record) != label(record) for rule in remaining)
            if score > best_score:
                best = record
                best_score = score
        assert best is not None and best_score > 0, (mode, "one-axis coverage")
        suite.append(best)
        used.add(key(best))
        remaining = [rule for rule in remaining if dv(rule, best) == label(best)]


def canonical_records(mode: str):
    for count in (1, 2, 3, 4, 5):
        for size in range(len(FLAGS) + 1):
            for items in itertools.combinations(FLAGS, size):
                flags = tuple(sorted(items))
                for target in SOURCES:
                    for sources in itertools.product(SOURCES, repeat=count):
                        alerts = tuple(
                            {"id": "V%d" % (index + 1), "source": source, "at": index + 1}
                            for index, source in enumerate(sources)
                        )
                        yield {"mode": mode, "flags": flags, "target": target, "alerts": alerts}


def exact_repair(mode: str, labeled: list[dict]) -> None:
    attempts = 0
    while True:
        attempts += 1
        assert attempts < 4000, (mode, "semantic repair")
        witness = None
        for rule in ALL_FAMILY:
            if not all(dv(rule, record) == label(record) for record in labeled):
                continue
            witness = next((record for record in canonical_records(mode) if dv(rule, record) != label(record)), None)
            if witness is not None:
                break
        if witness is None:
            return
        assert key(witness) not in {key(record) for record in labeled}
        labeled.append(witness)


def isolation(labeled: list[dict]):
    for direction in PICKS:
        for kind in ("PATCH", "MITIGATE"):
            def scorer(record, direction=direction, kind=kind):
                if kind == "PATCH":
                    choices = [item for item in record["alerts"] if item["source"] == record["target"]]
                else:
                    choices = [item for item in record["alerts"] if related(record["target"], item["source"])]
                if choices:
                    return kind + " " + choose(choices, direction)["id"]
                return "DISMISS"
            if all(scorer(record) == label(record) for record in labeled):
                return (direction, kind)
    for value in ("DISMISS", "WATCH", "AGGREGATE"):
        if all(label(record) == value for record in labeled):
            return value
    return None


def write_fresh(records: list[dict]) -> None:
    payloads = tuple(serialize(record) + "\n" for record in records)
    lines = ["def fresh_records():", "    return ("]
    lines.extend("        %r," % payload for payload in payloads)
    lines.append("    )")
    FRESH_PATH.write_text("\n".join(lines) + "\n")


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    HIDDEN.mkdir(parents=True, exist_ok=True)
    old_public = DATA / "cases.txt"
    if old_public.exists():
        old_public.unlink()
    for path in HIDDEN.glob("held_*.txt"):
        path.unlink()

    labeled_all = []
    held_all = []
    fresh_all = []
    mode_stats = {}
    for mode in MODES:
        labeled, held, vectors = build_mode(mode)
        if mode == "W1":
            ensure_held(labeled, held, vectors, lambda record: action(record) == "DISMISS")
            ensure_held(labeled, held, vectors, r1_own_pick_record)
        if mode == "W2":
            ensure_held(labeled, held, vectors, r2_boundary_record)
        used = {key(record) for record in labeled + held}
        fresh = choose_fresh(mode, used)
        audit = pool(mode, FRESH_POOL_N)
        repair_full(mode, labeled, held + fresh + audit, vectors)
        for source in SOURCES:
            ensure(labeled, held + fresh, vectors, lambda record, source=source: record["target"] == source)
            ensure(labeled, held + fresh, vectors, lambda record, source=source: any(item["source"] == source for item in record["alerts"]))
        for flag in FLAGS:
            ensure(labeled, held + fresh, vectors, lambda record, flag=flag: flag in record["flags"])
        for size in range(len(FLAGS) + 1):
            for items in itertools.combinations(FLAGS, size):
                flags = tuple(sorted(items))
                ensure(labeled, held + fresh, vectors, lambda record, flags=flags: record["flags"] == flags)
        ensure(labeled, held + fresh, vectors, lambda record: not record["flags"])
        if mode == "W1":
            ensure(labeled, held + fresh, vectors, r1_own_pick_record)
            ensure(labeled, held + fresh, vectors, lambda record: own_count(record) == 1 and peer_count(record) == 0 and label(record).split()[0] == "PATCH")
            ensure(labeled, held + fresh, vectors, lambda record: not record["flags"] and own_count(record) == 1 and peer_count(record) == 1 and label(record).split()[0] == "MITIGATE")
            ensure(labeled, held + fresh, vectors, lambda record: "exploited" in record["flags"] and record["target"] not in ("U4", "U5") and own_count(record) >= 2 and peer_count(record) == 0 and label(record).split()[0] == "PATCH")
        if mode == "W2":
            ensure(labeled, held + fresh, vectors, r2_boundary_record)
            ensure(labeled, held + fresh, vectors, lambda record: own_count(record) == 1 and peer_count(record) == 0 and label(record).split()[0] != "PATCH")
            ensure(labeled, held + fresh, vectors, lambda record: own_count(record) == 2 and peer_count(record) == 0 and label(record).split()[0] == "PATCH")
            ensure(labeled, held + fresh, vectors, lambda record: "exploited" in record["flags"] and record["target"] not in ("U4", "U5") and own_count(record) >= 2 and peer_count(record) == 0 and label(record).split()[0] == "PATCH")
        if mode == "W3":
            ensure(labeled, held + fresh, vectors, lambda record: label(record) == "AGGREGATE" and len(record["alerts"]) == 1 and all(related(record["target"], item["source"]) for item in record["alerts"]))
            ensure(labeled, held + fresh, vectors, lambda record: label(record) == "AGGREGATE" and len(record["alerts"]) == 2 and all(related(record["target"], item["source"]) for item in record["alerts"]))
            ensure(labeled, held + fresh, vectors, lambda record: own_count(record) == 1 and peer_count(record) == 0 and label(record).split()[0] != "PATCH")
            ensure(labeled, held + fresh, vectors, lambda record: own_count(record) == 2 and peer_count(record) == 0 and label(record).split()[0] == "PATCH")
            ensure(labeled, held + fresh, vectors, lambda record: "exploited" in record["flags"] and record["target"] not in ("U4", "U5") and own_count(record) >= 2 and peer_count(record) == 0 and label(record).split()[0] == "PATCH")
        ensure(labeled, held + fresh, vectors, lambda record: all(related(record["target"], item["source"]) for item in record["alerts"]))
        for count in (1, 2, 3, 4, 5):
            ensure(labeled, held + fresh, vectors, lambda record, count=count: len(record["alerts"]) == count)
        ensure(labeled, held + fresh, vectors, lambda record: len([item for item in record["alerts"] if item["source"] == record["target"]]) == 1)
        ensure(labeled, held + fresh, vectors, lambda record: len([item for item in record["alerts"] if item["source"] == record["target"]]) >= 2)
        ensure(labeled, held + fresh, vectors, lambda record: len([item for item in record["alerts"] if related(record["target"], item["source"])]) == 1)
        ensure(labeled, held + fresh, vectors, lambda record: len([item for item in record["alerts"] if related(record["target"], item["source"])]) >= 2)
        ensure(labeled, held + fresh, vectors, lambda record: len({item["source"] for item in record["alerts"] if related(record["target"], item["source"])}) >= 2)
        exact_repair(mode, labeled)
        cover_one_axis_rules(mode, labeled, held, vectors, labeled + held)
        cover_one_axis_rules(mode, labeled, fresh, vectors, labeled + held + fresh)
        check_defaults(mode, labeled)
        check_held_axes(mode, held)
        assert isolation(labeled) is None, (mode, "per-alert scorer")
        survivors = check_wide(mode, labeled, held + fresh + audit)
        assert sum(1 for record in held if dv(NAIVE, record) != label(record)) >= 5, (mode, "weak fixed boundary")
        assert sum(1 for record in fresh if dv(NAIVE, record) != label(record)) >= 10, (mode, "weak fresh boundary")
        labeled_all.extend(labeled)
        held_all.extend(held)
        fresh_all.extend(fresh)
        mode_stats[mode] = (len(labeled), survivors)

    check_r2_boundary(
        [record for record in labeled_all if record["mode"] == "W2"],
        [record for record in held_all if record["mode"] == "W2"],
        [record for record in fresh_all if record["mode"] == "W2"],
    )
    check_r1_own_pick_boundary(
        [record for record in labeled_all if record["mode"] == "W1"],
        [record for record in held_all if record["mode"] == "W1"],
        [record for record in fresh_all if record["mode"] == "W1"],
    )

    R.shuffle(labeled_all)
    assert len(labeled_all) >= 84
    assert {action(record) for record in labeled_all} == {"PATCH", "MITIGATE", "AGGREGATE", "WATCH", "DISMISS"}

    for rule in ALL_FAMILY:
        assert any(dv(rule, record) != label(record) for record in labeled_all), ("global rule", rule)

    for record in labeled_all + held_all + fresh_all:
        assert record["alerts"]
        assert all(item["source"] in SOURCES and item["at"] > 0 for item in record["alerts"])
    for mode in MODES:
        public = [record for record in labeled_all if record["mode"] == mode]
        challenge = [record for record in held_all + fresh_all if record["mode"] == mode]
        assert {len(record["alerts"]) for record in challenge} <= {len(record["alerts"]) for record in public}
        assert {record["flags"] for record in challenge} <= {record["flags"] for record in public}
        assert {record["target"] for record in challenge} <= {record["target"] for record in public}

    refs = {}
    for index, record in enumerate(held_all):
        filename = "held_%02d.txt" % index
        (HIDDEN / filename).write_text(serialize(record) + "\n")
        refs[filename] = label(record)

    fixed_actions = [action(record) for record in held_all]
    assert set(fixed_actions) == {"PATCH", "MITIGATE", "AGGREGATE", "WATCH", "DISMISS"}
    assert Counter(fixed_actions).most_common(1)[0][1] <= len(fixed_actions) // 2
    public_keys = {key(record) for record in labeled_all}
    assert all(key(record) not in public_keys for record in held_all + fresh_all)

    (DATA / "archive.txt").write_text("\n\n".join(serialize(record, label(record)) for record in labeled_all) + "\n")
    (HIDDEN / "reference.json").write_text(json.dumps(refs, indent=2, sort_keys=True) + "\n")
    write_fresh(fresh_all)

    print("labeled=%d held=%d fresh=%d alternatives=%d" % (len(labeled_all), len(held_all), len(fresh_all), len(ALL_FAMILY)))
    for mode in MODES:
        count, survivors = mode_stats[mode]
        print("%s labeled=%d survivors=%d" % (mode, count, survivors))


if __name__ == "__main__":
    main()
