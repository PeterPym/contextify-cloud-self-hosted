"""Additive device management wire contract; machine IDs remain opaque strings."""

import unicodedata
import uuid
from datetime import datetime
from typing import Self

from pydantic import (
    AliasChoices,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError


class IdentityProof(BaseModel):
    identity_instance_id: uuid.UUID | None = None
    hardware_fingerprint_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    fingerprint_kind: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_.:-]{1,80}$")

    @model_validator(mode="after")
    def paired_fingerprint(self) -> Self:
        if bool(self.hardware_fingerprint_hash) != bool(self.fingerprint_kind):
            raise PydanticCustomError(
                "device_identity_invalid", "Fingerprint hash and kind must be supplied together"
            )
        if self.hardware_fingerprint_hash and not self.identity_instance_id:
            raise PydanticCustomError(
                "device_identity_invalid", "Fingerprint requires an installation instance"
            )
        return self


class RenameDevice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str | None

    @field_validator("display_name")
    @classmethod
    def valid_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not 1 <= len(value) <= 80 or any(unicodedata.category(c).startswith("C") for c in value):
            raise PydanticCustomError(
                "device_identity_invalid", "Use 1–80 characters without controls"
            )
        return value


class ClaimDevice(IdentityProof):
    model_config = ConfigDict(extra="forbid")
    identity_instance_id: uuid.UUID
    request_id: uuid.UUID
    expected_identity_revision: int = Field(ge=0)
    expected_lifecycle_revision: int = Field(0, ge=0)
    machine_name: str = Field(min_length=1, max_length=256)
    os: str | None = None
    app_version: str | None = None
    source_offline_attested: bool = Field(
        False, validation_alias=AliasChoices("source_offline_attested", "source_offline")
    )


class MergeDevice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: uuid.UUID
    expected_merge_revision: int = Field(ge=0)
    into_device_id: str = Field(min_length=1, max_length=256)


class DeviceView(BaseModel):
    device_record_id: uuid.UUID
    device_id: str
    machine_id: str
    machine_name: str
    reported_name: str
    display_name: str | None
    short_id: str
    os: str | None
    app_version: str | None
    active: bool
    merged: bool
    canonical_device_id: str
    constituent_device_ids: list[str]
    merged_into_device_id: str | None
    last_sync_at: datetime | None
    last_seen_at: datetime | None
    activity: str
    adoption_eligible: bool
    adoption_available_at: datetime | None
    hardware_fingerprint_hash: str | None
    fingerprint_kind: str | None
    identity_instance_id: uuid.UUID | None
    identity_revision: int
    identity_last_request_id: uuid.UUID | None
    identity_last_request_kind: str | None
    identity_last_payload_hash: str | None
    merge_revision: int
    merge_last_request_id: uuid.UUID | None
    merge_last_request_kind: str | None
    merge_last_payload_hash: str | None
    lifecycle_revision: int
    lifecycle_last_request_id: uuid.UUID | None = None
    lifecycle_last_request_kind: str | None = None
    lifecycle_last_payload_hash: str | None = None
    retired_at: datetime | None
    removed_at: datetime | None


class DeviceDirectory(BaseModel):
    device_identity_version: int = 1
    device_lifecycle_version: int = 1
    retirement_coverage_version: int = 1
    devices: list[DeviceView]


class RetireDevice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: uuid.UUID
    expected_lifecycle_revision: int = Field(ge=0)
    expected_last_sync_at: AwareDatetime | None
    identity_instance_id: uuid.UUID


class RestoreDevice(BaseModel):
    """CAS input shared by explicit reactivation and list removal."""
    model_config = ConfigDict(extra="forbid")
    request_id: uuid.UUID
    expected_lifecycle_revision: int = Field(ge=0)
    expected_retired_at: AwareDatetime
