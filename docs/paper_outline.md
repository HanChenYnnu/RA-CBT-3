# Paper Outline for CBRCA Manuscript

## Title candidates

1. Context-Bound Credential and Rule-Composed Authorization for API-Facing LLM Services
2. Formal Context-Aware Authorization with Frozen Comparable Evaluation for LLM APIs
3. An Implementation-Grounded Formal Method for Context-Aware LLM API Access Control

## Abstract skeleton

- **Problem:** API-facing LLM services need access control that handles credential misuse and mixed-load contention without collapsing benign service.
- **Approach:** We present CBRCA, combining context-bound credentialing, explicit rule-composed multi-action authorization, and frozen comparable evaluation.
- **Formalization:** We provide explicit authorization semantics and core safety-property proofs under the stated model.
- **Evaluation:** We report B2 vs B4 results on S4 core, S4/S8 attribution, held-out synthetic/OOD slices, and shared-seed robustness.
- **Scope:** Claims are limited to the stated semantic model and synthetic/OOD evidence.

## 1. Introduction

### Subsections
- 1.1 Operational problem in API-facing LLM authorization
- 1.2 Gap in current practice
- 1.3 Contributions and scope

**Intent:** Establish the concrete problem, motivate why context-bound and multi-action control are needed, and state scoped contributions without overclaiming.

## 2. Related Work

### Subsections
- 2.1 API credential and token-control practices
- 2.2 Risk-adaptive authorization and throttling
- 2.3 Formal policy semantics in applied systems

**Intent:** Position CBRCA as an implementation-grounded formal method, not a universal replacement theory; clarify differentiation by explicit semantics plus frozen comparative evidence.

## 3. Problem Definition

### Subsections
- 3.1 System model and actors
- 3.2 Threat and misuse model
- 3.3 Evaluation objective and operating criteria

**Intent:** Define the exact decision setting and objective metrics, including non-deny attack success and benign service continuity.

## 4. Formal Method

### Subsections
- 4.1 State, environment, and judgment forms
- 4.2 Credential/context/risk/contention rules
- 4.3 Action composition algebra
- 4.4 Replay-evidence accumulation

**Intent:** Present the full formal method so each authorization outcome is traceable to explicit rules and composition.

## 5. Formal Properties

### Subsections
- 5.1 Hard-violation and invalid-credential safety properties
- 5.2 Monotonicity and non-downgrade properties
- 5.3 Determinism and replay non-neutralization

**Intent:** Provide proof-backed guarantees under the explicit model and separate proof claims from empirical findings.

## 6. System Realization / Implementation Mapping

### Subsections
- 6.1 Mapping rules to policy module
- 6.2 Mapping credential/context logic to runtime module
- 6.3 Conformance testing boundary

**Intent:** Show how the abstract semantics are concretely realized and where implementation tests validate conformance.

## 7. Experimental Setup

### Subsections
- 7.1 Compared methods and ablations
- 7.2 Scenario families and slice roles (S4/S5/S6/S7/S8)
- 7.3 Metrics, seed policy, and frozen protocol

**Intent:** Make evaluation reproducible and comparable, emphasizing frozen-stack design and slice responsibilities.

## 8. Results

### Subsections
- 8.1 Core S4 B2 vs B4 outcomes
- 8.2 Operating-point security/availability tradeoff
- 8.3 Multi-seed consistency

**Intent:** Present primary quantitative results with restrained interpretation tied to predefined metrics.

## 9. Ablation and Held-Out Validation

### Subsections
- 9.1 S4/S8 attribution matrix
- 9.2 Held-out family analysis
- 9.3 S8 hard-slice interpretation

**Intent:** Attribute gains to method components and assess robustness on held-out synthetic/OOD slices.

## 10. Discussion / Limitations

### Subsections
- 10.1 What is established
- 10.2 What remains out of scope
- 10.3 Risks to external validity

**Intent:** Explicitly delimit claims to the modeled semantics and synthetic/OOD evidence, with no deployment overclaim.

## 11. Conclusion

### Subsections
- 11.1 Summary of contributions
- 11.2 Practical implications
- 11.3 Next validation steps

**Intent:** Conclude with precise contribution scope: formalized method, core proofs, and frozen comparative evidence.
