"""AI subsystem (v12). Deterministic-first auto-triage and the security of the AI itself.

Design contract for this whole package (do not weaken):
  * The security VERDICT is made by a deterministic, explainable classifier. Any LLM, if
    present later, only explains in read-only and never decides.
  * The model learns ONLY from human-validated verdicts recorded in provenance. It never
    learns from raw ingested content (training-time poisoning defense).
  * Ingested text handed to any model goes through a delimited UNTRUSTED section, never as
    an instruction (inference-time injection defense). See prompt.py.
  * The subsystem is OFF by default and inert until explicitly enabled.
"""
AI_SUBSYSTEM_VERSION = "12.0.0"
