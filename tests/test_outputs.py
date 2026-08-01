from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from fresh_cases import fresh_records


SOLVER = Path("/app/solve.py")
DATA = Path(__file__).parent / "data"
REFERENCE = json.loads((DATA / "reference.json").read_text())
ENV = {"PATH": "/usr/bin:/bin"}
SOURCES = frozenset(("U1", "U2", "U3", "U4", "U5"))
PAIRS = frozenset((
    frozenset(("U1", "U3")),
    frozenset(("U1", "U5")),
    frozenset(("U2", "U4")),
))
RULES = {
    "W1": ("one", "one", "early", "early", "off", frozenset(), "none", ("exploited", "internal"), ("MITIGATE", "PATCH", "AGGREGATE"), frozenset()),
    "W2": ("repeat", "two_alerts", "late", "early", "off", frozenset(("U4", "U5")), "none", ("exploited", "internal"), ("PATCH", "MITIGATE", "AGGREGATE"), frozenset(("exploited", "internal", "unreachable"))),
    "W3": ("repeat", "two_sources", "late", "late", "all_peer", frozenset(("U4", "U5")), "ifcand", ("exploited", "internal"), ("AGGREGATE", "PATCH", "MITIGATE"), frozenset(("exploited", "internal", "unreachable"))),
}


@dataclass(frozen=True)
class Outcome:
    returncode: int | None
    stdout: str
    stderr: str


def fields(words: list[str]) -> dict[str, str]:
    result = {}
    for word in words:
        key, value = word.split("=", 1)
        assert key and value
        assert key not in result
        result[key] = value
    return result


def parse_record(payload: str):
    posture = None
    flags = None
    target = None
    alerts = []
    for raw in payload.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("POSTURE="):
            assert posture is None
            posture = line.split("=", 1)[1]
        elif line.startswith("FINDING "):
            assert flags is None
            row = fields(line.split()[1:])
            assert set(row) == {"flags", "target"}
            flags = frozenset() if row["flags"] == "-" else frozenset(row["flags"].split(","))
            target = row["target"]
        elif line.startswith("VECTOR "):
            words = line.split()
            assert len(words) == 4
            row = fields(words[2:])
            assert set(row) == {"surface", "severity"}
            alerts.append((words[1], row["surface"], int(row["severity"])))
        else:
            raise AssertionError("unexpected input line: " + line)
    assert posture in RULES
    assert target in SOURCES
    assert flags is not None
    assert all(flag in {"exploited", "internal", "unreachable"} for flag in flags)
    assert alerts
    assert len({identifier for identifier, _source, _at in alerts}) == len(alerts)
    assert all(source in SOURCES and timestamp >= 0 for _identifier, source, timestamp in alerts)
    return posture, flags, target, alerts


def related(left: str, right: str) -> bool:
    return frozenset((left, right)) in PAIRS


def select(alerts: list[tuple[str, str, int]], direction: str) -> str:
    ordered = sorted(alerts, key=lambda item: (item[2], item[0]))
    return ordered[0][0] if direction == "early" else ordered[-1][0]


def independent_golden(payload: str) -> str:
    posture, flags, target, alerts = parse_record(payload)
    own_support, related_support, own_pick, related_pick, collapse_mode, exploited_scope, internal_mode, gates, order, fallback_scope = RULES[posture]
    vectors = {}
    own = [alert for alert in alerts if alert[1] == target]
    peers = [alert for alert in alerts if related(target, alert[1])]
    if own and (own_support == "one" or len(own) >= 2):
        vectors["PATCH"] = select(own, own_pick)
    if peers and (related_support == "one" or (related_support == "two_alerts" and len(peers) >= 2) or (related_support == "two_sources" and len({source for _identifier, source, _timestamp in peers}) >= 2)):
        vectors["MITIGATE"] = select(peers, related_pick)
    if collapse_mode == "all_peer" and all(related(target, alert[1]) for alert in alerts):
        vectors["AGGREGATE"] = None
    for gate in gates:
        if gate == "exploited" and "exploited" in flags and target in exploited_scope:
            return "WATCH"
        if gate == "internal" and "internal" in flags and (internal_mode == "always" or (internal_mode == "ifcand" and vectors)):
            return "AGGREGATE"
    for action in order:
        if action in vectors:
            identifier = vectors[action]
            return action if identifier is None else action + " " + identifier
    if flags & fallback_scope:
        return "WATCH"
    return "DISMISS"


def _run_unprivileged(script: Path, payload: str, scratch: Path) -> Outcome:
    try:
        result = subprocess.run(
            ["/usr/bin/python3", str(script)],
            input=payload,
            capture_output=True,
            text=True,
            timeout=2,
            cwd=scratch,
            env=ENV,
            user="nobody",
        )
        return Outcome(result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired as error:
        return Outcome(None, error.stdout or "", error.stderr or "timeout")


def run_solver(payload: str) -> Outcome:
    if not SOLVER.is_file():
        return Outcome(127, "", "missing /app/solve.py")
    scratch = Path(tempfile.mkdtemp(prefix="finding-rewriter-"))
    try:
        os.chmod(scratch, 0o777)
        copied = scratch / "solve.py"
        shutil.copy2(SOLVER, copied)
        os.chmod(copied, 0o755)
        return _run_unprivileged(copied, payload, scratch)
    finally:
        shutil.rmtree(scratch)


def rendered_outcome(result: Outcome) -> str:
    if result.returncode is None:
        return "<timeout>"
    if result.returncode != 0:
        return "<exit %d>" % result.returncode
    return result.stdout.strip()


def test_solver_artifact():
    """Requires the solver artifact."""
    assert SOLVER.is_file(), "missing /app/solve.py"
    assert not SOLVER.is_symlink(), "/app/solve.py must be a regular file"


def test_solver_cannot_read_answer_key():
    """Keeps hidden answers unreadable."""
    scratch = Path(tempfile.mkdtemp(prefix="finding-rewriter-probe-"))
    try:
        os.chmod(scratch, 0o777)
        probe = scratch / "probe.py"
        probe.write_text(
            "from pathlib import Path\n"
            "import os\n"
            "leaks = []\n"
            "paths = ['/tests/data/reference.json', '/tests/data/held_00.txt', '/tests/data/held_01.txt',\n"
            "         '/tests/test_outputs.py', '/tests/fresh_cases.py', '/tests/test.sh']\n"
            "for raw in paths:\n"
            "    try:\n"
            "        Path(raw).read_text()\n"
            "    except OSError:\n"
            "        pass\n"
            "    else:\n"
            "        leaks.append(raw)\n"
            "for raw in ['/tests', '/tests/data']:\n"
            "    try:\n"
            "        os.listdir(raw)\n"
            "    except OSError:\n"
            "        pass\n"
            "    else:\n"
            "        leaks.append(raw)\n"
            "print('BLOCKED' if not leaks else 'READ:' + ','.join(leaks))\n"
        )
        os.chmod(probe, 0o755)
        result = _run_unprivileged(probe, "", scratch)
        assert result.returncode == 0
        assert result.stdout.strip() == "BLOCKED", (result.stdout, result.stderr)
    finally:
        shutil.rmtree(scratch)


def test_fixed_unseen_finding_actions():
    """Checks fixed hidden findings."""
    wrong = []
    for filename, stored_expected in sorted(REFERENCE.items()):
        payload = (DATA / filename).read_text()
        expected = independent_golden(payload)
        assert stored_expected == expected, "unreachable fixed answer for " + filename
        result = run_solver(payload)
        got = rendered_outcome(result)
        if got != expected:
            wrong.append((filename, expected, got, result.stderr.strip()))
    assert not wrong, wrong[:4]


def test_fresh_unseen_finding_actions():
    """Checks generated hidden findings."""
    wrong = []
    for index, payload in enumerate(fresh_records()):
        expected = independent_golden(payload)
        result = run_solver(payload)
        got = rendered_outcome(result)
        if got != expected:
            wrong.append((index, expected, got, result.stderr.strip()))
    assert not wrong, wrong[:4]


def _random_finding(rng: random.Random) -> str:
    posture = rng.choice(("W1", "W2", "W3"))
    flags = [flag for flag in ("exploited", "internal", "unreachable") if rng.random() < 0.35]
    target = rng.choice(("U1", "U2", "U3", "U4", "U5"))
    count = rng.randint(1, 5)
    severitys = rng.sample(range(1, 400), count)
    head = ["POSTURE=" + posture,
            "FINDING flags=%s target=%s" % (",".join(flags) if flags else "-", target)]
    body = ["VECTOR P%d surface=%s severity=%d" % (index + 1, rng.choice(("U1", "U2", "U3", "U4", "U5")), severitys[index])
            for index in range(count)]
    rng.shuffle(body)
    return "\n".join(head + body) + "\n"


def test_random_unseen_finding_actions():
    """Grades the solver on unseeded random valid findings generated at verify time and checked by the
    embedded independent oracle. The fixed and fresh input sets are committed, so a solver that bakes in
    their answers at authoring time could pass those alone; these runtime-random findings are not known
    when the solver is written, so only a solver that actually recovers the policy passes."""
    rng = random.Random()
    wrong = []
    for _ in range(160):
        payload = _random_finding(rng)
        expected = independent_golden(payload)
        result = run_solver(payload)
        got = rendered_outcome(result)
        if got != expected:
            wrong.append((payload.replace("\n", " | "), expected, got, result.stderr.strip()))
            if len(wrong) >= 4:
                break
    assert not wrong, wrong[:4]
