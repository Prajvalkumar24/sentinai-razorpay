# SentinAI — Two-Tier Multi-Agent Risk Engine

SentinAI is an autonomous, low-latency payment risk adjudication gateway built to eliminate false declines while protecting merchants against carding velocity attacks.

## Architecture
- Tier-1: Heuristic & Sliding-Window Feature Store (<5ms)
- Tier-2: Multi-Agent Consensus Adjudication (Behavioral + Merchant Risk)

## Setup
1. pip install fastapi uvicorn pydantic google-genai
2. python main.py
3. Open http://127.0.0.1:8000
