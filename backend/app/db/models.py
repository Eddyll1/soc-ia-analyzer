"""Esquema SQLite. Esquema canónico único: una tabla 'event' para todos los Excel."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (JSON, Column, DateTime, Float, ForeignKey, Integer,
                        String, Text)
from sqlalchemy.orm import relationship

from .database import Base


class Analysis(Base):
    __tablename__ = "analysis"
    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="draft")          # draft | analyzed | error
    profile = Column(String, default="CIS")
    event_count = Column(Integer, default=0)
    time_start = Column(String, nullable=True)
    time_end = Column(String, nullable=True)
    max_severity = Column(String, nullable=True)
    stats_json = Column(JSON, nullable=True)
    normalizations_json = Column(JSON, nullable=True)
    limitations_json = Column(JSON, nullable=True)
    ai_mode = Column(String, nullable=True)
    security_log_json = Column(JSON, nullable=True)

    events = relationship("Event", back_populates="analysis", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="analysis", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="analysis", cascade="all, delete-orphan")
    iocs = relationship("Ioc", back_populates="analysis", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="analysis", cascade="all, delete-orphan")


class Event(Base):
    __tablename__ = "event"
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey("analysis.id"), index=True)
    log_id = Column(String, index=True)
    timestamp = Column(String, nullable=True)
    host = Column(String, nullable=True)
    event_id = Column(String, nullable=True)
    user = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    destination = Column(String, nullable=True)
    log_source = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    command_line = Column(Text, nullable=True)
    result = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    extra_json = Column(JSON, nullable=True)

    analysis = relationship("Analysis", back_populates="events")


class Finding(Base):
    __tablename__ = "finding"
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey("analysis.id"), index=True)
    incident_id = Column(String, nullable=True)
    rule_id = Column(String)
    title = Column(String)
    severity_hint = Column(String)
    evidence_json = Column(JSON)            # lista de Log_ID
    summary = Column(Text)
    entity_json = Column(JSON)

    analysis = relationship("Analysis", back_populates="findings")


class Incident(Base):
    __tablename__ = "incident"
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey("analysis.id"), index=True)
    code = Column(String)                  # INC-A, INC-B...
    title = Column(String, nullable=True)
    severity = Column(String)
    confidence = Column(String, nullable=True)
    narrative = Column(Text, nullable=True)
    mitre_json = Column(JSON, nullable=True)
    timeline_json = Column(JSON, nullable=True)
    entities_json = Column(JSON, nullable=True)
    evidence_json = Column(JSON, nullable=True)
    justification = Column(Text, nullable=True)
    recommended_action = Column(Text, nullable=True)

    analysis = relationship("Analysis", back_populates="incidents")


class Ioc(Base):
    __tablename__ = "ioc"
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey("analysis.id"), index=True)
    type = Column(String)
    value = Column(String)
    context = Column(String, nullable=True)

    analysis = relationship("Analysis", back_populates="iocs")


class Report(Base):
    __tablename__ = "report"
    id = Column(Integer, primary_key=True)
    analysis_id = Column(Integer, ForeignKey("analysis.id"), index=True)
    kind = Column(String)                  # ejecutivo | tecnico
    content_md = Column(Text)
    generated_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    analysis = relationship("Analysis", back_populates="reports")
