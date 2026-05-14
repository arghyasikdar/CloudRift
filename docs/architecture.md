# CloudRift Architecture

CloudRift is organized as a staged intelligence pipeline:

```mermaid
flowchart TD
  A["Target"] --> B["Candidate Generation"]
  B --> C["Provider Fingerprinting"]
  C --> D["Async Provider Validation"]
  D --> E["Exposure Analysis"]
  E --> F["Sensitive File Detection"]
  F --> G["Relationship Correlation"]
  G --> H["Risk Scoring"]
  H --> I["Report Rendering"]
```

Provider support is implemented behind `CloudStorageProvider`, making new providers a small adapter rather than a rewrite.
