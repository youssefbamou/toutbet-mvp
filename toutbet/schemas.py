"""Validation stricte des entrées (pydantic) : types stricts, champs inconnus refusés."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterIn(_Strict):
    username: StrictStr = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    password: StrictStr = Field(min_length=10, max_length=128)


class LoginIn(_Strict):
    username: StrictStr = Field(min_length=1, max_length=32)
    password: StrictStr = Field(min_length=1, max_length=128)


class AmountIn(_Strict):
    amount_cents: StrictInt = Field(gt=0)


class BetIn(_Strict):
    title: StrictStr = Field(min_length=3, max_length=140)
    description: StrictStr = Field(default="", max_length=1000)
    min_stake_cents: StrictInt = Field(default=100, gt=0)
    bookie_fee_bp: StrictInt = Field(default=0, ge=0)
    closes_at: StrictInt  # timestamp Unix (secondes)
    invitees: list[StrictStr] = Field(default_factory=list, max_length=100)

    @field_validator("invitees")
    @classmethod
    def _unique(cls, v):
        if len({x.lower() for x in v}) != len(v):
            raise ValueError("invités en double")
        return v


class InviteIn(_Strict):
    usernames: list[StrictStr] = Field(min_length=1, max_length=100)


class WagerIn(_Strict):
    outcome: Literal["YES", "NO"]
    amount_cents: StrictInt = Field(gt=0)


class ResultIn(_Strict):
    outcome: Literal["YES", "NO"]


class DisputeIn(_Strict):
    reason: StrictStr = Field(min_length=3, max_length=500)


class SettleIn(_Strict):
    outcome: Literal["YES", "NO"] | None = None


class WebhookIn(_Strict):
    event_id: StrictStr = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    type: Literal["payment.succeeded"]
    username: StrictStr = Field(min_length=3, max_length=32)
    amount_cents: StrictInt = Field(gt=0)
