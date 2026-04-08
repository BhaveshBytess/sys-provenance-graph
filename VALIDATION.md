# Validation Results - Real-World Dataset Testing

## Section 1: Datasets Used
- Source: OTRF/Security-Datasets (Mordor)
- Baseline file: psh_python_webserver (Python webserver execution, benign-like)
- Attack file: metasploit_logonpasswords_lsass_memory_dump (LSASS credential dumping campaign)
- Format: JSONL (one JSON object per line), Sysmon Event ID 1 (process creation)

## Section 2: Experiment 1 - Cross-Dataset Detection (Smoke Test)
- Method: Trained baseline on smaller benign dataset, tested against attack dataset
- Results:
  - Total events loaded: 272
  - Events passed validation: 272
  - Anomalies detected: 269 (99%)
  - Unknown relationships: 269
  - Rare relationships: 0
- Analysis: Nearly everything flagged as anomalous because the baseline was too small and from a different environment. This demonstrates that a frequency-based model is only as good as its training data. An undersized or mismatched baseline produces no useful signal.

## Section 3: Experiment 2 - Same-Environment Split Test
- Method: Loaded larger attack dataset, split 70/30. First 70% used as baseline training, last 30% as test data.
- Results:
  - Total events loaded: 269
  - Events passed validation: 269
  - Anomalies detected: 1
  - Unknown relationships: 1
  - Rare relationships: 0
  - Flagged pair: cmd.exe -> dxdiag.exe (CRITICAL)
- Analysis: With adequate baseline data from the same environment, false positives dropped to near zero. The single detection - cmd.exe spawning dxdiag.exe - is consistent with post-exploitation system enumeration during a credential-dumping campaign.

## Section 4: Experiment 3 - Graph-Enriched Split Test
- Method: Same 70/30 split as Experiment 2, with graph analysis layer added.
- Results:
  - Baseline graph: 35 nodes, 38 edges
  - Test graph: 7 nodes, 6 edges
  - Anomalies detected: 1
  - Anomalies with graph risk factors: 1
  - Flagged pair: cmd.exe -> dxdiag.exe (CRITICAL)
  - Graph risk factors:
    1. Child process dxdiag.exe was never seen in baseline
    2. Relationship cmd.exe -> dxdiag.exe does not exist in baseline process graph
    3. dxdiag.exe is a new leaf node in test activity, never seen in baseline
- Analysis: The graph layer adds structural explainability beyond frequency counts. It identifies not just THAT a relationship is unknown, but WHY it is structurally suspicious - the child is an entirely new node, the edge is unprecedented, and the process appears as a terminal leaf consistent with enumeration behavior.

## Section 5: Key Takeaways
1. Baseline quality is everything. A frequency-based model with inadequate training data produces 99% false positives.
2. Same-environment training dramatically reduces noise. The 70/30 split dropped false positives from 269 to 0.
3. Graph-based enrichment adds explainability without replacing the core detection logic. It answers "why is this suspicious" in structural terms.
4. The single real detection (cmd.exe -> dxdiag.exe) is consistent with known post-exploitation behavior in the Mordor LSASS campaign dataset.
