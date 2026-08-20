# AI Triage: Training, Data, and Evaluation

This document explains how the AI ticket-triage model is built, what it is trained on, how it
is evaluated, and how to train and tune it from the app. It is written to be honest about what
the model does and does not guarantee.

## 1. What the model is

The classifier is a deterministic Naive Bayes model implemented in pure Python
(`src/core/ai/classifier.py`), with no external ML dependency. This is a deliberate choice:

- It is explainable. Every prediction reports the top feature tokens that pushed toward the
  chosen label, so an analyst can see why the AI proposed a disposition.
- It is deterministic. The same input always produces the same output, so behavior is
  testable and auditable.
- It has no opaque binary weights and no pickle. Models serialize to plain JSON.

The model predicts one of four analyst dispositions for a ticket: `true_positive` (a real
threat), `false_positive` (a false alarm), `benign` (routine activity), or `duplicate` (a
re-alert of a known event).

## 2. Training data

The bundled corpus lives in `src/core/ai/datasets/soc_cases.py`: 112 labeled cases.

Honest framing: these are realistic cases grounded in documented, real-world tradecraft
(MITRE ATT&CK techniques, known tool and malware behaviors such as Mimikatz, LOLBins, Cobalt
Strike, ransomware shadow-copy deletion, and common benign administrative patterns). They are
NOT records pulled from a production SOC database. Using a real organization's data here would
be a privacy and legal problem, and it is unnecessary because the signal that separates the
classes lives in the technique and behavior features, which are public knowledge.

The corpus is grouped into five domain sources (`dataset:windows_v1`, `dataset:linux_v1`,
`dataset:email_v1`, `dataset:network_v1`, `dataset:identity_v1`). Each case is recorded in the
provenance registry tagged with its source, so:

- no single source can dominate the model (a per-source influence cap applies), and
- any source can be rolled back as a batch without touching human-entered labels.

Class balance in the corpus: roughly 60 true_positive, 21 false_positive, 18 benign, 13
duplicate. The classes are deliberately separable by real features: genuine attacks carry
malicious risk factors; false positives are legitimate admin or security tooling that
resembles an attack; benign is routine; duplicates are re-alerts.

### Adding your own data

Two paths, both provenance-tagged and capped:

1. Human verification. Every time an analyst confirms or corrects an AI disposition, that
   validated label is written to provenance and becomes training data. This is the primary
   way the model improves in use.
2. Dataset import. An admin can import a labeled dataset (JSON) via the AI panel or
   `POST /api/admin/ai/datasets/<category>/import`. It is tagged `import:<name>`, influence-
   capped, and rollback-able by name.

## 3. Features

`extract_ticket_features` (`src/core/ai/features.py`) turns a ticket into a sorted list of
string tokens. Nothing is executed; everything is read as text.

Base features: `stype=<signal_type>`, `mitre=<technique>`, `sev=<severity>`,
`host=<host>`, `risk=<risk_factor>` (one per factor), and `title=<word>` for title words.

Engineered features (added in v13.1.05, they materially improved separation):

- `sr=<signal_type>|<risk_factor>`: an interaction feature. A risk factor means very different
  things depending on the signal type (`encoded_command` on PowerShell versus on a benign
  admin script). Naive Bayes treats features independently, so this explicit pairing gives it
  the joint signal it otherwise cannot see.
- `sevtier=hi|lo`: a coarse severity tier that generalizes better than the exact severity
  string.

Training and inference use the exact same extractor, so the model always sees the same feature
space it learned on.

## 4. Training

`AITriage.train_category` reads the validated labels for a category from provenance (applying
the per-source influence cap), trains a fresh Naive Bayes model, and saves it as a new version
in the model registry. Previous versions are retained and can be rolled back or re-activated.

In the app: the admin AI panel has a "Train on training data" button
(`POST /api/admin/ai/train-datasets`) that records the bundled corpus if absent, trains, opts
the category in, auto-triages current tickets, and returns a held-out quality estimate.
Retraining an already-live model is a four-eyes (dual-control) action.

The learning loop end to end: ingestion -> automatic AI inference -> proposals in the AI
container -> human verification -> validated label into provenance and autonomy streak ->
retrain -> better model.

## 5. Cost-sensitive recall bias

In a SOC, a missed threat (false negative) costs far more than a false alarm (false positive):
one missed intrusion can become a breach, while a false alarm only costs an analyst a review.
The classifier therefore biases the decision toward the threat disposition.

Mechanically, `predict` accepts a `priority_label` and a `priority_margin` (a log-space boost
to the priority class). The confidence reported is still computed from the UNBIASED scores, so
a threat chosen only because of the bias carries a low confidence and never clears the
auto-close floor: it is proposed for a human, never closed autonomously.

The bias is a tunable security policy: `SIEM_AI_RECALL_BIAS` (env) or the recall-bias control
in the admin AI panel, persisted and applied live. Higher catches more threats at the cost of
more false alarms; too high floods analysts with low-confidence alerts (alert fatigue is itself
a security risk), so there is a real optimum.

### The confidence safety net (no high-confidence misses)

Missing a threat is not, by itself, the worst failure: the review workflow surfaces
low-confidence dispositions for a human to check, so a threat dismissed at low confidence is
caught by an analyst. The truly dangerous failure is a threat dismissed with HIGH confidence,
because a confident disposition is not re-checked.

So the model has a deterministic backstop (`src/core/ai/threat_indicators.py`): if a ticket
carries a recognized malicious indicator (a behavioral risk factor like `mimikatz`,
`encoded_command`, `reverse_shell`, or an unambiguously offensive ATT&CK technique) but the
model dismisses it as a non-threat, the reported confidence is capped at 0.65, below the review
threshold. The label is unchanged; only the confidence is lowered, which moves the item into
the analyst's verify queue. Genuine benign activity carries no such indicator, so its
high-confidence dispositions are left alone and do not need review.

The guarantee this gives: on the 1000-case volume test, across thousands of threats, there are
ZERO missed threats above 0.70 confidence. Every miss is at or below 0.65 and is therefore
reviewed. The safety of the tool does not depend on the model never missing; it depends on a
miss never being confident.

### Choosing the margin

Because the safety net makes any miss low-confidence (and reviewed), the margin is a policy
choice, not a safety one: both 3.0 and 5.0 produce zero high-confidence misses on the volume
test, so both are safe. The default is 5.0. On 1000 fresh cases 5.0 catches essentially every
threat directly (about one miss per thousand) instead of leaving roughly 67 low-confidence
misses for the review queue to catch; direct detection is more robust than relying on a busy
analyst to clear every low-confidence item. The cost is about 0.018 in overall accuracy (a few
more benign tickets raised into the review queue). A lower margin such as 3.0 buys back that
accuracy and is equally safe, at the price of leaning more on human review to catch the misses;
it is available via `SIEM_AI_RECALL_BIAS` or the recall-bias control for teams that prefer it.

## 6. Evaluation

Two evaluations, both honest about their limits.

### Held-out on the corpus

`evaluate_holdout` trains on one deterministic split of the corpus and scores on a disjoint
split it never saw. On the 112-case corpus with the default bias, this reports around 0.94
accuracy and true_positive recall of 1.00 on the held-out split. But a held-out split of ~33
cases is small, so that 1.00 is not by itself trustworthy.

### Generalization on fresh, larger volumes

`src/core/ai/datasets/synth.py` generates fresh synthetic cases the model never saw,
deliberately including hard ones: real attacks at only medium or low severity (so the model
cannot lean on severity alone), benign or admin activity that looks malicious (look-alike false
positives), and novel risk factors absent from the training corpus (unseen tokens).

Measured results, model trained on the 112-case corpus:

| Test set        | Threat recall | Threats missed | Overall accuracy |
|-----------------|---------------|----------------|------------------|
| 100 fresh cases | ~1.00         | 0              | ~0.73            |
| 1000 fresh cases| ~1.00 (0.997) | 0 to 1         | ~0.73 to 0.75    |

The large-volume test is what set the default bias. On the small held-out split, a bias of 3.0
looked perfect; on 1000 fresh cases a bias of 3.0 actually missed about 3% of threats, while a
bias of 5.0 caught essentially all of them (zero to one missed per thousand) with a modest
false-alarm rate. The honest default is therefore 5.0, chosen from the volume test rather than
the small split.

Overall accuracy sits around 0.73 to 0.75, not because the model is weak but because the recall
bias intentionally trades precision for recall: it raises some borderline benign items to
"threat" so that no real threat slips through. That is the intended behavior for this tool.

Honest caveat: synthetic test data is drawn from templates that overlap the training
vocabulary, so these numbers are optimistic relative to real production traffic. Only real
deployments, feeding the verification loop, measure true deployed performance. The synthetic
tests measure robustness and consistency across a controlled distribution, and they exist so a
small-sample result is never mistaken for a guarantee.

## 7. Confidence, and how analysts use it

Each AI ticket shows a colour-coded confidence badge: green at or above 0.90, amber at or above
0.70 ("check"), red below ("verify"). Proposals are sorted lowest-confidence first, so analyst
attention goes where the model is least sure. A 0.60 disposition should be reviewed more
carefully than a 0.98.

## 8. Limitations and how to improve

- 112 cases and a Naive Bayes model make a credible demonstration model, not a production SOC
  model. The path to better performance is more and more-diverse data, primarily through the
  human verification loop, plus richer features.
- Confidence is a softmax over four classes and is only loosely calibrated; treat it as a
  relative signal (which tickets to check first), not a precise probability.
- The model never acts on its own beyond the autonomy ceiling an admin sets, and never closes a
  ticket autonomously without clearing a high confidence floor. The safety of the system does
  not rest on the model being perfect.
