# Title and Abstract Candidates

## Title candidates
1. Context-Bound Credential and Rule-Composed Authorization for API-Facing LLM Services
2. Formal Context-Aware Authorization with Frozen Comparable Evaluation for LLM APIs
3. An Implementation-Grounded Formal Method for Context-Aware LLM API Access Control

## Abstract candidate

We study authorization for API-facing LLM services under mixed benign and adversarial traffic. We present Context-Bound Credential and Rule-Composed Authorization (CBRCA), an implementation-grounded formal method that combines context-bound credentialing, explicit rule-composed multi-action decisions (`allow`, `throttle`, `deny`), and replay-aware evidence accumulation. We formalize the method with explicit state/judgment semantics and prove core properties under the stated model, including hard-violation deny, monotonicity, composition non-downgrade, determinism, and replay non-neutralization. We then evaluate CBRCA in a frozen comparable protocol against baseline B2, including core S4 results, full S4/S8 ablation attribution, held-out synthetic/OOD families, and shared-seed robustness. Results support improved discrimination and reduced non-deny attack success on hard slices while maintaining benign service at the reported operating point. Claims are limited to the explicit formal model and synthetic/OOD evidence; we do not claim a fully general access-control theory or production-deployment validation.
