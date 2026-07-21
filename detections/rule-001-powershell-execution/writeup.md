# Rule 001: PowerShell Executing mshta.exe (Download Cradle)

## ATT&CK Mapping
- **Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
- **Tactic:** Execution (TA0002)

## Detection Logic
```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName contains "powershell.exe"
| where CommandLine contains "mshta.exe"
```
- `contains` is used instead of `==` for substring matching, since `NewProcessName` holds a full file path that varies by system. `contains` is case-insensitive; `==` is case-sensitive (case-insensitive equivalent: `=~`; case-sensitive equivalent of `contains` is `contains_cs`).
- Detects PowerShell spawning `mshta.exe` as a child process — a known living-off-the-land "download cradle" pattern (Atomic Red Team T1059.001, Test #8).

## Why No Threshold/Aggregation
This is a low base-rate combination — legitimate IT operations rarely produce PowerShell launching mshta.exe together. Aggregating or thresholding would only delay detection of something already anomalous on first occurrence. Alerts fire on every match.

## False-Positive Analysis
No common legitimate business use for this exact combination was identified. This is a low-confidence-of-benign pattern; unlike broad rules (e.g., "any PowerShell execution"), this rule targets a specific technique combination rather than a common admin activity, so it doesn't carry a documented FP source yet. **Open item:** legacy software installers occasionally use `mshta` for GUI prompts and could theoretically be wrapped in a PowerShell deployment script — not observed yet in this lab, but flagged here as something to revisit if this rule ever fires in testing on a false positive.

## Known Blind Spots
1. **`pwsh.exe` (PowerShell Core)** is not detected — the string `"pwsh.exe"` does not contain the substring `"powershell.exe"`. Future iteration should add a second `contains` check for `pwsh.exe`, or replace with a regex matching both.
2. **`powershell_ise.exe`** does not contain the substring `"powershell.exe"` either (due to the `_ise` inserted before `.exe`), so PowerShell ISE-originated execution is also missed by this rule.
