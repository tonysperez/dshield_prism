"""Pydantic response models for the console API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SearchCandidate(BaseModel):
    type: str
    id: str
    label: str
    score: float | None = None


class SearchResponse(BaseModel):
    query: str
    candidates: list[SearchCandidate]


class GraphNode(BaseModel):
    data: dict[str, Any]


class GraphEdge(BaseModel):
    data: dict[str, Any]


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    anchor: dict[str, str]  # {type, id}


class IOCDetail(BaseModel):
    type: str
    id: str
    title: str
    summary: dict[str, Any]
    raw: dict[str, Any] | None = None
    # One-line "how strong is the evidence" verdict (same vocabulary the
    # inbox row carries). Populated by format_anchor_evidence_quality for
    # playbook / campaign / *_cluster / ip anchors; empty for kinds where
    # a verdict doesn't apply (asn, country, session, command).
    # Consumed by the graph orientation card.
    evidence_quality: str = ""


class TableRow(BaseModel):
    row: dict[str, Any]


class TableResponse(BaseModel):
    total: int
    rows: list[dict[str, Any]]
    page: dict[str, int] = Field(default_factory=lambda: {"from": 0, "size": 0})


class HealthResponse(BaseModel):
    ok: bool
    elasticsearch_version: str | None = None
    cluster_name: str | None = None
    indexes: dict[str, str]
    doc_counts: dict[str, Any]
    # ISO-8601 timestamp of the freshest rollup doc — drives the
    # "data Xm ago" badge in the topbar. None when no rollup data
    # exists yet (fresh install) or when the lookup errored.
    last_data_ts: str | None = None
    error: str | None = None
