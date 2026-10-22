"""Machine-group v1 inputs. Unknown filters fail closed."""

import re
import uuid
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic_core import PydanticCustomError

from contextify_cloud.device_schemas import ClaimDevice, RenameDevice


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProjectSelector(Input):
    kind: Literal["project_id", "repo_group_key"]
    value: str = Field(min_length=1, max_length=512)

    @field_validator("value")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise PydanticCustomError(
                "group_input_invalid", "Use a nonblank exact Cloud identifier"
            )
        return value


class CreateGroup(Input):
    name: str
    visibility: Literal["private", "team"] = "private"
    project_selector: ProjectSelector | None = None

    @field_validator("name")
    @classmethod
    def name_valid(cls, value: str) -> str:
        return RenameDevice.valid_name(value) or ""


class EditGroup(Input):
    name: str | None = None
    project_selector: ProjectSelector | None = None
    expected_revision: int = Field(ge=0)

    @field_validator("name")
    @classmethod
    def name_valid(cls, value: str | None) -> str | None:
        return RenameDevice.valid_name(value)


class JoinGroup(Input):
    device_id: str = Field(min_length=1, max_length=256)
    # Fresh enrollment uses precisely the identity service's request/CAS contract.
    claim: ClaimDevice | None = None
    identity_instance_id: uuid.UUID | None = None
    join_token: SecretStr | None = None


class MemberEdit(Input):
    device_record_id: uuid.UUID
    expected_revision: int = Field(ge=0)


class CreateToken(Input):
    create_request_id: uuid.UUID
    expires_in: int = Field(3600, ge=1, le=86400)
    max_uses: int = Field(1, ge=1, le=100)


class AcknowledgeToken(Input):
    delivery_acknowledged: Literal[True]


class ProjectScope(Input):
    mode: Literal["default", "all", "ids", "repo"] = "default"
    project_ids: list[str] = Field(default_factory=list, max_length=100)
    repo_group_key: str | None = Field(None, min_length=1, max_length=512)
    this_worktree: bool = False

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.mode != "ids" and self.project_ids:
            raise PydanticCustomError("group_input_invalid", "project_ids requires ids mode")
        if any(not p.strip() or p != p.strip() or len(p) > 512 for p in self.project_ids):
            raise PydanticCustomError("group_input_invalid", "Invalid project ID")
        if (self.mode == "repo") != bool(self.repo_group_key):
            raise PydanticCustomError(
                "group_input_invalid", "repo mode requires exactly one repo_group_key"
            )
        if self.repo_group_key and not self.repo_group_key.strip():
            raise PydanticCustomError("group_input_invalid", "Invalid repo key")
        if self.this_worktree and (self.mode != "ids" or len(self.project_ids) != 1):
            raise PydanticCustomError(
                "group_input_invalid", "this_worktree requires one exact project ID"
            )
        return self


class TokenList(Input):
    include_inactive: bool = False
    limit: int = Field(50, ge=1, le=100)
    offset: int = Field(0, ge=0, le=100000)


def lexical_query(value: str) -> str:
    # A colon in prose, a time or a URL is punctuation, not a column filter.
    patterns = [
        (r"\b(?:AND|OR|NOT)\b", "remove Boolean operators and use plain terms"),
        (r"\bNEAR\s*\(", "remove NEAR(...) and use plain terms"),
        (r'"', "remove quotation marks; phrase syntax is not supported"),
        (r"\S+\*", "remove '*' and use whole words"),
        (r"(?:^|(?<=[\s(]))[A-Za-z_]\w*:(?!//)(?=\S)",
         "remove ':' (column filters are not supported) and use plain terms"),
        (r"[{}]", "remove braces and use plain terms"),
    ]
    for pattern, remedy in patterns:
        match = re.search(pattern, value)
        if match:
            raise PydanticCustomError(
                "group_input_invalid", f"Unsupported lexical token {match.group(0)!r}; {remedy}",
            )
    return value


class GroupQuery(Input):
    contract_version: Literal[1] = 1
    q: str = Field("", max_length=4096)
    project_scope: ProjectScope = Field(
        default_factory=lambda: ProjectScope(mode="default", repo_group_key=None)
    )
    mine: bool = False
    device_id: str | None = Field(None, min_length=1, max_length=256)
    since: int | None = None
    until: int | None = None
    kinds: list[Literal["user", "assistant", "system", "summary"]] = Field(default_factory=list)
    transcript_id: str | None = Field(None, min_length=1, max_length=512)
    exclude_session_ids: list[str] = Field(default_factory=list, max_length=100)
    joined_device_id: str | None = Field(None, min_length=1, max_length=256)
    identity_instance_id: uuid.UUID | None = None
    limit: int = Field(20, ge=1, le=100)
    offset: int = Field(0, ge=0, le=100000)

    _lexical = field_validator("q")(lexical_query)

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if bool(self.joined_device_id) != bool(self.identity_instance_id):
            raise PydanticCustomError(
                "group_input_invalid", "Joined assertion requires device and instance"
            )
        if self.since is not None and self.until is not None and self.since > self.until:
            raise PydanticCustomError("group_input_invalid", "since must not exceed until")
        return self
