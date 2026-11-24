"""SQL is built from constants; values always go in as parameters (%s).

Identifiers are built with psycopg.sql. A few f-strings remain where SQL is put
together from fixed fragments defined in the code (status filters, the policy
preview's conditions, an ORDER BY chosen from two literals). This test finds every
f-string that looks like SQL and fails if it interpolates anything not on the list
below, so a request value can't slip into SQL unnoticed (#33). Adding to the list is
a review decision: the new expression must only ever hold text written in the code.
"""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "fleetwright"
SQL = re.compile(r"\b(SELECT|UPDATE|INSERT|DELETE|WITH|LISTEN|FROM|WHERE|SET)\b")

# file -> expressions allowed inside SQL f-strings, each a constant fragment from the code
ALLOWED = {
    "actions/admin.py": {"UNREACHABLE_SQL", "fleet.AUTO_UPDATING_SQL", "gateway.outdated_sql()"},
    # base: joined from fixed conditions with %s placeholders; sql, k: STATUS_FILTERS' fragments and keys
    "actions/hosts.py": {"base", "STATUS_FILTERS[status][1]", "sql", "k"},
    # order: one of two literal ORDER BY clauses
    "actions/runs.py": {"order"},
    # GLOB_RE: a fixed expression; where/param: from selection_sql, fixed conditions with %s placeholders
    "actions/schedules.py": {"GLOB_RE.format('g')", "where", "param"},
    # which: one of two literal conditions; outdated_sql(): a hex bundle id checked before it's inlined
    "gateway.py": {"which", "outdated_sql()", "bundle"},
    "notify.py": {"UNREACHABLE_SQL"},
}


def sql_fstrings():
    for path in sorted(ROOT.rglob("*.py")):
        rel = str(path.relative_to(ROOT))
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.JoinedStr):
                text = "".join(v.value for v in node.values if isinstance(v, ast.Constant))
                if SQL.search(text):
                    for v in node.values:
                        if isinstance(v, ast.FormattedValue):
                            yield rel, node.lineno, ast.unparse(v.value)


def test_sql_fstrings_only_interpolate_reviewed_constants():
    bad = [f"{f}:{line}: {{{expr}}}" for f, line, expr in sql_fstrings() if expr not in ALLOWED.get(f, set())]
    assert not bad, ("SQL built with an f-string around something that isn't a reviewed constant. Pass values "
                     "as %s parameters, build identifiers with psycopg.sql, or (for a fixed fragment) add it to "
                     "ALLOWED with a reason:\n  " + "\n  ".join(bad))


def test_the_allowed_list_has_nothing_stale():
    used = {(f, e) for f, _, e in sql_fstrings()}
    stale = [f"{f}: {e}" for f, exprs in ALLOWED.items() for e in exprs if (f, e) not in used]
    assert not stale, f"no longer used, remove from ALLOWED: {stale}"


def test_the_guard_catches_a_request_value():
    sample = 'db.fetch(f"SELECT * FROM hosts WHERE name = \'{request.query_params[\'q\']}\'")'
    node = next(n for n in ast.walk(ast.parse(sample)) if isinstance(n, ast.JoinedStr))
    exprs = [ast.unparse(v.value) for v in node.values if isinstance(v, ast.FormattedValue)]
    assert exprs and not set(exprs) & set().union(*ALLOWED.values())
