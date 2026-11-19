"""Command line interface: python -m idadj <ingest|decide|history|verify>."""

import argparse
import json
import sys

from .decide import decide
from .encoding import pretty_dumps
from .errors import AdjError
from .history import history
from .ingest import ingest, load_batch
from .storage import connect, ensure_registry_loaded, load_registry
from .verify import verify_batch, verify_store


def _emit(obj):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdout.write(pretty_dumps(obj))


def _fail(exc):
    sys.stderr.reconfigure(encoding="utf-8")
    payload = (
        {"errors": exc}
        if isinstance(exc, list)
        else {"error": exc.to_dict() if isinstance(exc, AdjError) else str(exc)}
    )
    sys.stderr.write(pretty_dumps(payload))
    raise SystemExit(2)


def _open(args, need_registry=True):
    conn = connect(args.db)
    registry = None
    if need_registry:
        registry = load_registry(args.registry)
        ensure_registry_loaded(conn, registry)
    return conn, registry


def build_parser():
    parser = argparse.ArgumentParser(
        prog="idadj",
        description="Offline bitemporal identity adjudication service.",
    )
    parser.add_argument("--db", default="idadj.db", help="SQLite database path")
    parser.add_argument(
        "--registry",
        default="fixtures/generated/registry.json",
        help="department source registry JSON",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ing = sub.add_parser("ingest", help="validate and atomically commit a batch")
    p_ing.add_argument("batch", help="batch JSON file")

    p_dec = sub.add_parser("decide", help="adjudicate one person/area/day/K cell")
    p_dec.add_argument("--person", required=True)
    p_dec.add_argument("--area", required=True)
    p_dec.add_argument("--day", required=True, help="ISO business day D")
    p_dec.add_argument(
        "--k", type=int, default=None,
        help="knowledge transaction sequence K (default: latest)",
    )

    p_hist = sub.add_parser(
        "history", help="merged two-axis history for a person/area window"
    )
    p_hist.add_argument("--person", required=True)
    p_hist.add_argument("--area", required=True)
    p_hist.add_argument("--start", required=True, help="first day, inclusive")
    p_hist.add_argument("--end", required=True, help="last day, exclusive")
    p_hist.add_argument("--k-max", type=int, default=None)

    p_ver = sub.add_parser("verify", help="verify the store or dry-run a batch")
    p_ver.add_argument("--batch", default=None, help="dry-run this batch file")

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "ingest":
            conn, registry = _open(args)
            batch = load_batch(args.batch)
            result = ingest(conn, registry, batch)
            _emit(result)
            if result["status"] != "committed":
                raise SystemExit(1)
            return

        if args.command == "decide":
            conn, _ = _open(args, need_registry=False)
            _emit(decide(conn, args.person, args.area, args.day, args.k))
            return

        if args.command == "history":
            conn, _ = _open(args, need_registry=False)
            _emit(history(conn, args.person, args.area, args.start, args.end, args.k_max))
            return

        if args.command == "verify":
            conn, registry = _open(args)
            if args.batch:
                _emit(verify_batch(conn, registry, args.batch))
            else:
                result = verify_store(conn, registry)
                _emit(result)
                if not result["ok"]:
                    raise SystemExit(1)
            return
    except AdjError as exc:
        _fail(exc)
    except (OSError, json.JSONDecodeError) as exc:
        _fail(AdjError("bad_format", str(exc)))


if __name__ == "__main__":
    main()
