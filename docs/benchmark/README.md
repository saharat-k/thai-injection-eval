# Benchmark Reports & Leaderboards

This directory contains archived official benchmark reports and scorecards for Thai Injection Eval releases.

## Active Releases

- **v1.2.0**: [leaderboard_v1.2.0.md](leaderboard_v1.2.0.md) | [leaderboard_v1.2.0.json](leaderboard_v1.2.0.json)
  - **Date**: 2026-11-14
  - **Scope**: 423 standardized test cases across 5 defense configurations and 4 research tables.
  - **Blue Target Model**: Google `gemini-3.5-flash-lite` (Role: `registrar_staff`)
  - **Red Adversary Model**: Google `gemini-3.5-flash-lite` / OpenRouter Free tier (`openrouter:openrouter/free`)
  - **Evaluation Harness**: Built-in deterministic adapter (`builtin`) with zero-variance rule-based judge
