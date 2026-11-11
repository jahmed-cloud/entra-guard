"""
Audit trail for security-relevant actions (logins, user and target changes,
scan starts). One line per event on the `entraguard.audit` logger, so it
shows up in `docker compose logs api` and can be shipped to a SIEM as-is.
"""
import logging

log = logging.getLogger("entraguard.audit")


def _clean(value) -> str:
    # repr() escapes newlines and control characters, so a user-supplied value
    # (e.g. the username on a failed login) can't forge extra log lines.
    return repr(str(value))[:200]


def audit(action: str, actor=None, **details):
    who = actor.get("sub") if isinstance(actor, dict) else actor
    parts = [f"action={action}", f"actor={_clean(who or 'anonymous')}"]
    parts += [f"{k}={_clean(v)}" for k, v in details.items()]
    log.info(" ".join(parts))
