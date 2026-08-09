"""Owned native fixture entry point used by :mod:`budobugs.labs.manager`."""

from __future__ import annotations

import argparse

import uvicorn


def main() -> None:
    """Run the localhost fixture while retaining an unambiguous ownership token."""

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--ownership-token", required=True)
    arguments = parser.parse_args()
    # The token intentionally remains in the process command line. LabManager
    # uses it only as a capability for exact process ownership verification.
    _ = arguments.ownership_token
    uvicorn.run(
        "budobugs.labs.fixture_app:app",
        host="127.0.0.1",
        port=arguments.port,
        access_log=False,
    )


if __name__ == "__main__":
    main()
