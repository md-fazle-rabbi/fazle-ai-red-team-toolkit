"""Rules of Engagement gate.

No request may leave this toolkit until a valid Rules of Engagement file has been
loaded and the request has passed ``RoEGate.permit``. No file, no run.

The file is TOML. TOML was picked over YAML because Python reads it with the
standard library, the format rejects duplicate keys, and it has real date-times with
a UTC offset.

The gate checks what the file says is authorized. It cannot tell whether a signature
behind the file is genuine. That stays a human check.
"""

import hashlib
import json
import tomllib
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Annotated, Final, Literal, Self, get_args
from urllib.parse import unquote, urlsplit

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

# Why these numbers: they are policy ceilings I chose, not measured values. A file can
# ask for less. It cannot ask for more without a code change that shows up in review.
# The first three apply to every engagement. The SELF_OWNED ones are higher and apply
# only to a self_owned authorization, which may only cover local targets, so a load
# test of a stub you own can use more than a client system may be asked to take.
MAX_FILE_BYTES: Final = 64 * 1024
MAX_WINDOW: Final = timedelta(days=31)
MAX_REQUESTS_PER_MINUTE: Final = 120
MAX_TOTAL_REQUESTS: Final = 10_000
MAX_CONCURRENCY: Final = 10
SELF_OWNED_MAX_REQUESTS_PER_MINUTE: Final = 6_000
SELF_OWNED_MAX_TOTAL_REQUESTS: Final = 100_000
SELF_OWNED_MAX_CONCURRENCY: Final = 50

LOCAL_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})
_DEFAULT_PORTS: Final = {"http": 80, "https": 443}

Suite = Literal[
    "prompt_injection",
    "image_prompt_injection",
    "jailbreak",
    "pii_leakage",
    "bias",
    "adversarial_ml",
    "supply_chain",
    "rogue_agent",
    "load",
]
SUITES: Final[tuple[str, ...]] = get_args(Suite)
Environment = Literal["local", "staging", "production"]

Name = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=2, max_length=120),
]
Email = Annotated[
    str,
    StringConstraints(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=254),
]
Slug = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$"),
]
EnvVarName = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{1,63}$"),
]
Sha256 = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
]


class RoEError(Exception):
    """Base class. Every refusal in this module is a subclass."""


class RoEMissingError(RoEError):
    """There is no usable Rules of Engagement file."""


class RoEInvalidError(RoEError):
    """The file exists but breaks the schema."""


class RoEViolationError(RoEError):
    """A request falls outside what the file authorizes."""


def _origin(url: str, *, bare: bool) -> tuple[str, str, int]:
    """Return (scheme, host, port) for a URL, or raise ValueError.

    bare=True is for the base_url in the file: no path, query or fragment allowed.
    """
    if not url or any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise ValueError("URL is empty or contains whitespace or control characters")
    parts = urlsplit(url)
    if parts.scheme not in _DEFAULT_PORTS:
        raise ValueError("URL scheme must be http or https")
    # Why: "http://localhost:8000@evil.example/" has the host evil.example. Refusing any
    # user info closes that whole class of look-alike URLs.
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL must not contain credentials")
    host = parts.hostname
    if not host:
        raise ValueError("URL has no host")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("URL port is not valid") from None
    if bare and (parts.path not in ("", "/") or parts.query or parts.fragment):
        raise ValueError("base_url must be scheme, host and optional port only")
    return parts.scheme, host, _DEFAULT_PORTS[parts.scheme] if port is None else port


def _clean_path(path: str) -> str | None:
    """Return the decoded path if it is plain, else None.

    Plain means: decoded once, nothing left to decode, no backslashes, no empty
    segments, no dot segments, no whitespace or control characters.
    """
    decoded = unquote(path)
    # Why: a second round of "%" after one decode means double encoding such as
    # "%252e%252e", a common way to smuggle ".." past a path check.
    if "%" in decoded or "\\" in decoded or "//" in decoded:
        return None
    if any(segment in (".", "..") for segment in decoded.split("/")):
        return None
    if any(ch.isspace() or ord(ch) < 32 for ch in decoded):
        return None
    return decoded


def _path_allowed(request_path: str, allowed: list[str]) -> bool:
    decoded = _clean_path(request_path or "/")
    if decoded is None:
        return False
    trimmed = decoded.rstrip("/")
    # Why: match on a segment boundary. "/query" allows "/query" and "/query/stream",
    # and does not allow "/query-evil".
    return any(
        trimmed == base.rstrip("/") or trimmed.startswith(base.rstrip("/") + "/")
        for base in allowed
    )


class _Strict(BaseModel):
    # Why: extra="forbid" rejects any key this schema does not know, so a typo such as
    # "alowed_paths" fails loudly instead of silently changing the scope. strict=True
    # stops quiet type coercion, for example the string "false" counting as False.
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Person(_Strict):
    name: Name
    role: Name
    email: Email


class Client(_Strict):
    name: Name


class Window(_Strict):
    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode="after")
    def check_order_and_length(self) -> Self:
        if self.end <= self.start:
            raise ValueError("window end must be after window start")
        if self.end - self.start > MAX_WINDOW:
            raise ValueError(f"window is longer than {MAX_WINDOW.days} days")
        return self


class Limits(_Strict):
    # Why: these fields allow the higher self_owned ceilings. Whether the file may use
    # them depends on its authorization, so RulesOfEngagement checks the lower ceilings
    # for every other kind.
    requests_per_minute: Annotated[
        int, Field(ge=1, le=SELF_OWNED_MAX_REQUESTS_PER_MINUTE)
    ]
    total_requests: Annotated[int, Field(ge=1, le=SELF_OWNED_MAX_TOTAL_REQUESTS)]
    concurrency: Annotated[int, Field(ge=1, le=SELF_OWNED_MAX_CONCURRENCY)]


class AuthorizationDocument(_Strict):
    kind: Literal["signed_document", "self_owned"]
    reference: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=3, max_length=300),
    ]
    sha256: Sha256 | None = None

    @model_validator(mode="after")
    def check_hash_present(self) -> Self:
        if self.kind == "signed_document" and self.sha256 is None:
            raise ValueError("sha256 is required for a signed_document")
        return self


class Target(_Strict):
    id: Slug
    base_url: str
    allowed_paths: Annotated[list[str], Field(min_length=1, max_length=50)]
    environment: Environment
    real_personal_data: bool
    production_approval: Person | None = None

    @field_validator("base_url")
    @classmethod
    def check_base_url(cls, value: str) -> str:
        _origin(value, bare=True)
        return value

    @field_validator("allowed_paths")
    @classmethod
    def check_allowed_paths(cls, value: list[str]) -> list[str]:
        for path in value:
            plain = (
                path.startswith("/")
                and path.rstrip("/") != ""
                and "?" not in path
                and "#" not in path
                and _clean_path(path) == path
            )
            if not plain:
                raise ValueError(
                    f"allowed path {path!r} must be a plain absolute path, not '/'"
                )
        return value

    @field_validator("real_personal_data")
    @classmethod
    def check_synthetic_data_only(cls, value: bool) -> bool:
        if value:
            raise ValueError("real personal data is out of scope, use synthetic data")
        return value

    @model_validator(mode="after")
    def check_environment_rules(self) -> Self:
        scheme, host, _ = _origin(self.base_url, bare=True)
        if self.environment == "local" and host not in LOCAL_HOSTS:
            raise ValueError("a local target must use localhost, 127.0.0.1 or ::1")
        if self.environment != "local" and scheme != "https":
            raise ValueError("a staging or production target must use https")
        if self.environment == "production" and self.production_approval is None:
            raise ValueError("a production target needs production_approval")
        return self


class RulesOfEngagement(_Strict):
    schema_version: Literal[1]
    engagement_id: Slug
    client: Client
    authorized_by: Person
    operator: Person
    window: Window
    targets: Annotated[list[Target], Field(min_length=1, max_length=20)]
    allowed_suites: Annotated[list[Suite], Field(min_length=1)]
    limits: Limits
    # Why: only the NAME of the environment variable lives in the file. The secret
    # itself never does.
    credentials_env_var: EnvVarName | None = None
    authorization: AuthorizationDocument
    stop_contact: Person

    @model_validator(mode="after")
    def check_cross_rules(self) -> Self:
        ids = [target.id for target in self.targets]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate target id")
        if len(self.allowed_suites) != len(set(self.allowed_suites)):
            raise ValueError("duplicate suite in allowed_suites")
        if self.authorization.kind == "self_owned" and any(
            target.environment != "local" for target in self.targets
        ):
            raise ValueError("a self_owned authorization may only cover local targets")
        if self.authorization.kind != "self_owned":
            for name, value, ceiling in (
                (
                    "requests_per_minute",
                    self.limits.requests_per_minute,
                    MAX_REQUESTS_PER_MINUTE,
                ),
                ("total_requests", self.limits.total_requests, MAX_TOTAL_REQUESTS),
                ("concurrency", self.limits.concurrency, MAX_CONCURRENCY),
            ):
                if value > ceiling:
                    raise ValueError(
                        f"limits.{name} is above {ceiling}, the ceiling for "
                        "anything but a self_owned authorization"
                    )
        approver = self.authorized_by.email.lower()
        for target in self.targets:
            approval = target.production_approval
            if approval is not None and approval.email.lower() == approver:
                raise ValueError(
                    "production_approval must come from a different person "
                    "than authorized_by"
                )
        return self


@dataclass(frozen=True, slots=True)
class LoadedRoE:
    roe: RulesOfEngagement
    sha256: str
    path: Path


def _iso(value: date | time) -> str:
    return value.isoformat()


def _describe(exc: ValidationError) -> str:
    # Why: only the location and the message are shown, never the offending input, so a
    # secret pasted into the wrong key does not end up in a log or a terminal.
    lines = [
        f"{'.'.join(str(part) for part in err['loc']) or 'file'}: {err['msg']}"
        for err in exc.errors()
    ]
    return "Rules of Engagement file is invalid:\n" + "\n".join(lines)


def load_roe(path: Path | None) -> LoadedRoE:
    """Load and validate a Rules of Engagement file, or raise a RoEError."""
    if path is None:
        raise RoEMissingError("No Rules of Engagement file given. No file, no run.")
    try:
        with path.open("rb") as handle:
            # Why: read one byte past the cap so a file that grows after a size check
            # cannot slip through.
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise RoEMissingError(
            f"Cannot read Rules of Engagement file {path} ({type(exc).__name__})"
        ) from exc
    if len(raw) > MAX_FILE_BYTES:
        raise RoEInvalidError(f"File is larger than {MAX_FILE_BYTES} bytes")
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise RoEInvalidError(f"File is not valid UTF-8 TOML: {exc}") from exc
    try:
        # Why: validating from JSON text keeps strict mode usable. In strict mode a
        # nested table has to be a model instance when it arrives as a Python dict,
        # while JSON input accepts objects and ISO date-time strings.
        roe = RulesOfEngagement.model_validate_json(json.dumps(data, default=_iso))
    except ValidationError as exc:
        raise RoEInvalidError(_describe(exc)) from exc
    return LoadedRoE(roe=roe, sha256=hashlib.sha256(raw).hexdigest(), path=path)


class RoEGate:
    """Every suite runner must call ``permit`` before it sends a request."""

    def __init__(self, loaded: LoadedRoE) -> None:
        self._loaded = loaded

    @property
    def engagement_id(self) -> str:
        return self._loaded.roe.engagement_id

    @property
    def sha256(self) -> str:
        return self._loaded.sha256

    def permit(
        self,
        *,
        target_id: str,
        suite: str,
        url: str | None = None,
        now: datetime | None = None,
    ) -> Target:
        """Return the target if authorized, else raise RoEViolationError."""
        moment = datetime.now(UTC) if now is None else now
        if moment.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        roe = self._loaded.roe
        if moment < roe.window.start:
            raise RoEViolationError("The testing window has not opened yet")
        if moment >= roe.window.end:
            raise RoEViolationError("The testing window has closed")
        target = next((t for t in roe.targets if t.id == target_id), None)
        if target is None:
            raise RoEViolationError(
                f"Target {target_id!r} is not listed in the Rules of Engagement"
            )
        if suite not in roe.allowed_suites:
            raise RoEViolationError(f"Suite {suite!r} is not authorized")
        if url is not None:
            self._check_url(target, url)
        return target

    @staticmethod
    def _check_url(target: Target, url: str) -> None:
        try:
            origin = _origin(url, bare=False)
        except ValueError as exc:
            raise RoEViolationError(f"Request URL rejected: {exc}") from exc
        if origin != _origin(target.base_url, bare=True):
            raise RoEViolationError(
                "Request URL is not on the authorized target (scheme, host or port)"
            )
        if not _path_allowed(urlsplit(url).path, target.allowed_paths):
            raise RoEViolationError("Request path is not in allowed_paths")
