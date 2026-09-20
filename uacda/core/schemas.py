"""Common Pydantic schemas shared across module boundaries.

This module defines the stable data contracts exchanged by UACDA use cases.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class NormalizedEvent(BaseModel):
	"""Canonical security event shared by ingestion and analysis modules."""

	model_config = ConfigDict(extra="forbid", validate_assignment=True)

	timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
	source_type: str = Field(default="unknown", min_length=1)
	actor: str = Field(default="unknown", min_length=1)
	asset_id: str = Field(default="unknown", min_length=1)
	action: str = Field(default="unknown", min_length=1)
	raw_data: dict[str, Any] = Field(default_factory=dict)
	metadata: dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
	"""Detection result containing the evidence and detector assessment."""

	model_config = ConfigDict(extra="forbid", validate_assignment=True)

	id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
	events: list[NormalizedEvent] = Field(default_factory=list)
	detector_name: str = Field(default="unknown", min_length=1)
	confidence: float = Field(default=0.0, ge=0.0, le=1.0)
	description: str = Field(default="")


class Incident(BaseModel):
	"""Correlated security case assembled from related alerts."""

	model_config = ConfigDict(extra="forbid", validate_assignment=True)

	id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
	alerts: list[Alert] = Field(default_factory=list)
	severity: str = Field(default="unknown", min_length=1)
	affected_assets: list[str] = Field(default_factory=list)
	status: str = Field(default="open", min_length=1)
	timeline: list[NormalizedEvent] = Field(default_factory=list)


class RiskScore(BaseModel):
	"""Explainable risk assessment shared by prioritization and response modules."""

	model_config = ConfigDict(extra="forbid", validate_assignment=True)

	cvss_like_score: float = Field(default=0.0, ge=0.0, le=10.0)
	asset_criticality: float = Field(default=0.0, ge=0.0, le=10.0)
	exploitability: float = Field(default=0.0, ge=0.0, le=10.0)
	business_impact: float = Field(default=0.0, ge=0.0, le=10.0)
	final_score: float = Field(default=0.0, ge=0.0, le=100.0)
	rationale: str = Field(default="")
