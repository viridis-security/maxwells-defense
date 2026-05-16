---
name: Difficulty rule contribution
about: Share a difficulty-oracle rule from a real deployment
title: "[rule] "
labels: difficulty-rule, good-first-issue
---

**The rule, in pseudocode**

```python
def difficulty(context_id, signals):
    if ...:
        return ...
```

**Traffic shape it addresses**
- Attack pattern observed:
- Approximate scale:
- Why this rule discriminates legit traffic vs. attacker traffic:

**Performance impact**
- False positive rate (legit clients gated higher than necessary):
- False negative rate (attacker traffic still gets through):
- Median legit-client solve time:

**Generalizes to other deployments?**
Yes / No / Depends on:
