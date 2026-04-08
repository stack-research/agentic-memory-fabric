A reasonable starting point. Eric Kandel is one of the few researchers who connects molecular biology directly to the question “what is a memory.”

In Search of Memory (best entry point)

In Search of Memory is the most efficient way in.

It is part memoir, part science. The key idea unfolds gradually:
	•	Memory = changes in synaptic strength
	•	Learning = modifying connections between neurons
	•	Long-term memory = gene expression + structural change

Kandel demonstrates this through experiments on the sea slug Aplysia, where simple neural circuits make the mechanism visible and measurable.

This book answers your question at a physical level without requiring deep prior knowledge.

⸻

If you want to go deeper after that

Principles of Neural Science (reference-level)

Principles of Neural Science is the full system.

It moves from:
	•	ion channels
	•	to synapses
	•	to circuits
	•	to behavior

Memory appears as a multi-scale phenomenon across all of them.

This is not a casual read. It is closer to a map of the field.

⸻

What you’ll come away with (compressed)

After Kandel, the vague idea of “memory” usually collapses into something more concrete:
	•	Not stored like files
	•	Not localized to a single place
	•	Not static

Instead:
	•	distributed
	•	biochemical
	•	continuously rewritten

⸻

If you want a sharper edge after Kandel, the next useful contrast is to pair him with someone more computational (how memory behaves like a system rather than tissue).

-----

arXiv / papers (closest to what you’re asking)

These are not random papers—they define the current shape of the field.

1) Engrams + computation (bridge from Kandel → models)
	•	“Engram Memory Encoding and Retrieval: A Neurocomputational Perspective”
This is the most direct continuation of Kandel into computation.
Core idea:
	•	Memory = sparse neuron populations + plasticity rules
	•	Efficiency comes from sparsity + gating + interference control
It explicitly connects:
	•	synaptic plasticity → representations
	•	engrams → data structures

⸻

2) Key–value memory (brain ↔ transformers)
	•	“Key-Value Memory in the Brain”
This one is important because it reframes memory in a way you already understand from ML:
	•	“keys” = retrieval cues
	•	“values” = stored content
	•	separation improves retrieval fidelity
This is effectively:

attention ≈ biological memory lookup



⸻

3) Hippocampus as a content-addressable system
	•	“Bio-inspired computational memory model of the hippocampus”
Key idea:
	•	hippocampus ≈ content-addressable memory (CAM)
	•	retrieve whole memory from fragments
	•	implemented with spiking neural networks
This connects directly to:
	•	Hopfield networks
	•	vector databases
	•	approximate nearest neighbor search

⸻

4) Systems consolidation (time dimension of memory)
	•	“A Computational Model of Systems Memory Consolidation and Reconsolidation”
Core idea:
	•	memory moves: hippocampus → cortex over time
	•	retrieval rewrites the memory itself
This is closer to:

write → cache → long-term store → rewrite on read



⸻

5) Modern hybrid models (LLMs + brain ideas)
	•	“Vision-Language Episodic Memory Framework…”
Key idea:
	•	cortex = embedding model
	•	hippocampus = attractor memory system
	•	interaction = episodic memory pipeline
This is basically:

embeddings + retrieval + attractor dynamics



⸻

Books (computational perspective)

These are slower but give you durable mental models.

1) Theoretical Neuroscience — Dayan & Abbott

The closest thing to a “math-first Kandel.”

Covers:
	•	Hebbian learning
	•	attractor networks
	•	probabilistic models of memory

This is where memory becomes equations.

⸻

2) Neuronal Dynamics — Wulfram Gerstner et al.

Direct link to modern computational neuroscience.

Focus:
	•	spiking neurons
	•	plasticity rules (STDP)
	•	network-level memory behavior

This connects biology → simulation cleanly.

⸻

3) Memory Systems in the Brain — Rolls & Treves

Less trendy, but very precise.

Core contributions:
	•	hippocampus as associative memory
	•	attractor dynamics
	•	pattern completion / separation

⸻

4) Hopfield Networks and Physical Systems (papers, not a book)

You should read Hopfield directly.

Why:
	•	first clean formulation of memory as an energy landscape
	•	still relevant to transformers and diffusion models

⸻

How to think about the stack (compressed)

After reading these, memory stops being a vague idea and becomes something like:

Level 0: molecules (Kandel)
Level 1: synapses (plasticity rules)
Level 2: circuits (engrams)
Level 3: systems (hippocampus ↔ cortex)
Level 4: computation (key-value, attractors, embeddings)


⸻

If you want a tight reading path

Minimal sequence that compounds:
	1.	Kandel
	2.	Dayan & Abbott
	3.	“Key-Value Memory in the Brain”
	4.	Engram computational paper

That sequence moves you from:

biology → abstraction → formalization → modern synthesis


⸻

If useful, the next step is mapping these ideas directly onto LLM memory systems (vector DBs, RAG, long-context models, etc.).

The mapping works cleanly if you stop thinking of “memory” as storage and instead treat it as a set of cooperating systems with different time scales and failure modes.

Below is the direct correspondence.

⸻

1) The biological stack → LLM stack

Biology (compressed)
	•	hippocampus → fast, episodic, fragile
	•	cortex → slow, semantic, stable
	•	synapses → weights
	•	engrams → distributed traces
	•	recall → reconstruction, not playback

LLM systems (direct mapping)
	•	context window → working memory (hippocampus-like)
	•	vector DB / RAG → episodic memory store
	•	model weights → semantic memory (cortex-like)
	•	embeddings → engrams (distributed representations)
	•	inference → reconstruction

⸻

2) A minimal architecture (biologically aligned)

You can model an LLM system like this:

            [ USER INPUT ]
                   │
                   ▼
        ┌────────────────────┐
        │  Working Memory    │  ← context window
        └────────────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
[ Episodic Store ]     [ Semantic Store ]
 (vector DB)             (model weights)
        │                     │
        └──────────┬──────────┘
                   ▼
            [ RETRIEVAL ]
                   ▼
            [ RECONSTRUCTION ]
                   ▼
               [ OUTPUT ]

This is not analogy—it is structurally equivalent.

⸻

3) Key correspondences (where it gets interesting)

A) Engrams ↔ embeddings

In neuroscience:
	•	memory = sparse pattern across neurons

In ML:
	•	memory = vector in embedding space

Properties match:
	•	distributed
	•	lossy
	•	similarity-based retrieval

⸻

B) Hippocampus ↔ vector database

Hippocampus:
	•	rapid encoding
	•	content-addressable
	•	supports recall from fragments

Vector DB:
	•	fast writes
	•	nearest-neighbor retrieval
	•	partial query → full result

This is the cleanest 1:1 mapping.

⸻

C) Cortex ↔ model weights

Cortex:
	•	slow learning
	•	generalizes
	•	extracts structure

LLM:
	•	weights encode:
	•	language
	•	concepts
	•	abstractions

You don’t “store memories” here—you compress patterns into behavior.

⸻

D) Recall = reconstruction (critical insight)

Neither system retrieves exact data.

Instead:

retrieved signals + prior structure → reconstructed output

That’s why:
	•	humans misremember
	•	LLMs hallucinate

Same failure mode, different substrate.

⸻

4) Failure modes (almost identical)

Interference
	•	brain: overlapping engrams
	•	LLM: embedding collisions / bad retrieval

Drift
	•	brain: reconsolidation changes memory
	•	LLM: updated context shifts output

False recall
	•	brain: confabulation
	•	LLM: hallucination

These are not bugs—they are properties of reconstructive systems.

⸻

5) Time scales (this is where design matters)

Biology separates memory by time:
	•	milliseconds → working memory
	•	minutes–days → hippocampus
	•	weeks–years → cortex

You should do the same:

short-term   → context window
mid-term     → vector DB (RAG)
long-term    → fine-tuning / weights

Most systems fail because they collapse all three into one.

⸻

6) A more faithful LLM memory system

If you push the analogy further, you get:

Add consolidation

Move important RAG memories into weights over time:

RAG → training data → fine-tune → weights

Add forgetting

Decay low-value memories:

score(memory) ↓ over time → prune

Add reconsolidation

On retrieval:

retrieve → rewrite → store updated version

This mirrors how biological memory actually behaves.

⸻

7) The deeper insight

The key shift is this:

Memory is not storage.
Memory is a process that shapes future computation.

In both systems:
	•	the past is not preserved
	•	it is re-encoded to influence the next prediction

⸻

8) If you want to build this (Python sketch)

A minimal “hippocampus + cortex” system:

class MemorySystem:
    def __init__(self, embed, vectordb, model):
        self.embed = embed
        self.db = vectordb
        self.model = model

    def store(self, text):
        vec = self.embed(text)
        self.db.add(vec, text)

    def recall(self, query, k=5):
        qvec = self.embed(query)
        memories = self.db.search(qvec, k)
        return memories

    def respond(self, query):
        memories = self.recall(query)
        context = "\n".join(memories)
        return self.model.generate(query, context)

Missing pieces (intentionally):
	•	decay
	•	consolidation
	•	memory scoring
	•	rewriting

Those are the hard parts—and where biology still outperforms us.

⸻

9) Where this leads (agentic-memory-fabric)

Given an interest in:
	•	agent memory control planes
	•	storage systems

The frontier is not better storage. It is:
	•	memory lifecycle management
	•	trust / poisoning resistance
	•	decay + eligibility (an earlier question)
	•	multi-timescale coordination

That is essentially:

an "operating system for memory"

⸻

The next step is to design a concrete memory control plane (Postgres / vector DB / Redis) that actually implements these biological constraints instead of just storing embeddings.
