# Agentic Memory Fabric – Conversation Export

## Context
Discussion on biological memory (Eric Kandel), computational memory models, and mapping those ideas to LLM systems and agentic memory fabrics.

---

## Key Concepts

### Biological Memory
- Synaptic plasticity
- Engrams (distributed neural patterns)
- Hippocampus (episodic memory)
- Cortex (semantic memory)
- Memory is reconstructive, not stored exactly

### Computational Mapping
- Context window → working memory
- Vector DB → episodic memory
- Model weights → semantic memory
- Embeddings → engrams
- Retrieval → reconstruction

### Core Insight
Memory is not storage.  
Memory is a dynamic process that influences future computation.

---

## LLM Memory Architecture

Short-term:
- Context window

Mid-term:
- Vector database (RAG)

Long-term:
- Model weights (fine-tuning)

---

## Failure Modes (Shared with Biology)
- Interference (overlapping representations)
- Drift (reconsolidation changes)
- False recall (hallucination)

---

## Agentic Memory Fabric Direction

Shifts from:
- Storage-centric
to:
- Control-plane-centric

Key components:
- Memory lifecycle management
- Decay / forgetting
- Promotion (episodic → semantic)
- Trust / poisoning resistance
- Lineage tracking

---

## Suggested Enhancements for Systems

### 1. Decay Function
score = relevance * recency * reinforcement

### 2. Memory Promotion
frequent retrieval → abstraction → long-term storage

### 3. Reconsolidation
retrieve → update → store

### 4. Retrieval Gating
only query memory when uncertainty exceeds threshold

---

## Mental Model

Memory = dynamic, evolving, scored graph  
NOT a database

---

## Reading Path

1. Eric Kandel – In Search of Memory
2. Dayan & Abbott – Theoretical Neuroscience
3. Key-Value Memory (computational framing)
4. Engram-based computational models

---

## Next Step

Use this document as context input for deeper code traversal of:
https://github.com/stack-research/agentic-memory-fabric
