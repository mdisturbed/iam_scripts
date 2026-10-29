# Gap register (example)

Illustrative rows only. Copy into the engagement's working docs, replace the rows, then build the Gaps tab:

```
python tools/build_findings_review.py --register findings-register.md --gaps gap-register.md --out findings-review.xlsx
```

Findings stay in the findings register. This table holds everything else that is a gap:

- **Control:** a theme that groups findings.
- **Capability:** a missing or unused process or tool.
- **Evidence:** not assessed yet.
- **Coverage:** no script measures it.
- **Decision:** waiting on a decision.

Keep the columns in this order.

| ID | Type | Gap | Area | Current state | Target state | Impact | Priority | Related findings | Source | Owner | Status | Next step | Raised |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G-01 | Capability | No user access review process | Governance | No access reviews in the last 180 days (30); 0% of Tier 0 roles and groups under review (20) | Recurring reviews of privileged roles, guests and group memberships by owner | Access accumulates unchecked | High | F-12 | 30 and 20 runs; kickoff meeting | IAM Manager | Open | Confirm whether another tool runs reviews | 2026-01-15 |
| G-02 | Evidence | Azure RBAC not assessed | Identity | Run account holds no Azure role; no subscriptions visible (11 Blocked) | Reader at the root management group; 11 rerun | Azure privileged access unknown | High | | 11 run; access request | Cloud platform owner | In progress | Access requested | 2026-01-15 |
