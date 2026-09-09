# CloudSentinel Background Worker Architecture

## Purpose

CloudSentinel uses a background event worker to decouple event submission from event ingestion and processing.

## Current Flow

```text
Event Producer
      |
      v
EventWorker.submit()
      |
      v
In-Memory Queue
      |
      v
Background Worker Thread
      |
      v
Canonical Event Ingestion Pipeline
      |
      v
Normalize -> Validate
```

## Worker Responsibilities

- Accept events from producers.
- Queue events in memory.
- Process queued events asynchronously.
- Pass events through the canonical ingestion boundary.
- Support controlled startup and shutdown.

## Non-Responsibilities

The worker does not own detection rules, risk scoring, attack correlation, alert presentation, or dashboard logic.

## Shutdown Behavior

When stop() is called, the worker stops after queued events have been processed.

## Day 30 Scope

This architecture intentionally uses Python queue.Queue and threading.Thread.

A persistent message broker or distributed worker system is outside the scope of this stage.
