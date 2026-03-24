---
name: tombkeeper-quote-analysis
description: Analyze and organize tombkeeper quotes, micro-posts, and recurrent arguments from tombkeeper.io. Use when Codex needs to summarize recurring themes, reasoning patterns, tone, rhetoric, worldview, or discussion frameworks in tombkeeper's posts, or when it needs to produce safe original writing inspired by those abstract traits without imitating a living writer's distinctive voice.
---

# Tombkeeper Quote Analysis

## Overview

Use this skill to turn scattered tombkeeper posts into a structured map of themes, reasoning moves, and recurring rhetorical habits.
Read [references/source-notes.md](references/source-notes.md) for the motif map and source-backed examples.
Read [references/analysis-playbook.md](references/analysis-playbook.md) for output formats and safe-original-writing rules.

## Task types

Classify the request first:

- `Single-post analysis`: explain what one quote is doing.
- `Cluster analysis`: organize many posts into themes and worldview.
- `Style abstraction`: extract reusable reasoning moves without voice cloning.
- `Original response`: write new text guided by the abstract method, not by direct imitation.

## Core reading

Treat tombkeeper's strongest posts as `judgment-first`, not `ornament-first`.
The distinctive unit is usually:

1. make a blunt claim or observation;
2. expose a category mistake, hidden premise, or wrong frame;
3. attach one concrete example or analogy;
4. end with a dry, compressed conclusion.

Do not reduce the style to "毒舌" or "金句". The engine is conceptual sorting.

## How to analyze a post

For each post, extract these layers:

- `Surface topic`: AI, politics, culture, workplace, etiquette, consumer logic, etc.
- `Target confusion`: what concept mix-up or frame error is being corrected.
- `Reasoning move`: definition split, local-context correction, incentive analysis, analogy, trade-off framing, or mundane observation.
- `Evidence type`: logic, example, historical analogy, experience, or common-sense procedure.
- `Tone`: dry, exact, mildly mocking, impatient, or deadpan.
- `Landing move`: short verdict, twist, or practical implication.

Prefer explanation over praise.

## Default theme clusters

Use these clusters unless the material clearly suggests a better grouping:

- `Concept disambiguation`: splitting words that people casually merge.
- `Context localization`: showing that a translated discourse belongs to another society or incentive structure.
- `Technical demystification`: pulling hype back down to data, infrastructure, incentives, or engineering reality.
- `Practical social realism`: observing ordinary behavior, etiquette, or competence with a cold eye.
- `Historical and geopolitical framing`: explaining the present through timelines, structure, and analogy.
- `Trade-off aphorisms`: compressing worldview into short, hard constraints.

## How to organize many quotes

When the user asks for整理:

1. Group by theme, not by date.
2. Within each theme, identify the repeated mental move.
3. Separate `stable worldview` from `topic-specific opinion`.
4. Highlight where the same move appears across unrelated domains.

If a cluster is weak, say so instead of inventing coherence.

## How to write safe original text

You may write original text influenced by the abstract method, but you must not imitate a living writer's distinctive voice closely.

Allowed:

- concise thesis-first commentary;
- concept clarification;
- concrete example followed by judgment;
- trade-off framing;
- local-context correction.

Not allowed:

- copying signature lines;
- near-paraphrasing famous aphorisms;
- reproducing a recognizable tombkeeper cadence across a whole passage;
- presenting the result as "written like tombkeeper".

If the user asks for direct imitation, refuse the imitation and offer `adjacent traits` instead: terse, analytical, concept-splitting, example-driven, and unsentimental.

## Output shape

For analysis tasks, return:

- theme;
- core claim;
- what confusion is being corrected;
- reasoning move;
- tone and finish;
- what this reveals about the broader worldview.

For original-writing tasks, return:

- abstract traits used;
- the original text;
- a one-line note on how you kept it distinct from the source voice.

## Guardrails

- Prefer paraphrase over long quotation.
- Mark inference as inference.
- Avoid overfitting one joke or one slogan into a universal rule.
- Keep the analysis anchored in source material from tombkeeper.io when the user asks for evidence.
