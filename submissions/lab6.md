\# Lab 6 — Submission



\## Task 1: Checkov on Terraform



\### Terraform scan

\- \*\*Total checks:\*\* 129 (49 passed, 80 failed)

\- \*\*Secrets scan:\*\* 2 failed (CKV\_SECRET\_2, CKV\_SECRET\_6)



| Severity | Count |

|----------|------:|

| Critical | 1 (Hardcoded AWS credentials) |

| High | \~30 (IAM wildcard policies, public S3, exposed security groups) |

| Medium | \~25 (Missing encryption, logging, backups) |

| Low | \~24 (Missing descriptions, tags, best practices) |



\*Note: Checkov CE does not populate `severity` field for most rules without Bridgecrew API key. Severity estimates above are based on official Checkov documentation.\*



\### Top 5 rule IDs (by frequency)

| Rule ID | Count | What it checks |

|---------|------:|----------------|

| CKV\_AWS\_289 | 4 | IAM policies allow permissions management without constraints |

| CKV\_AWS\_355 | 4 | IAM policies allow "\*" as resource for restrictable actions |

| CKV\_AWS\_23 | 3 | Security group rules missing descriptions |

| CKV\_AWS\_288 | 3 | IAM policies allow data exfiltration |

| CKV\_AWS\_290 | 3 | IAM policies allow unconstrained write access |



\### Module-leverage analysis (Lecture 6 slide 17)

Looking at the top-5 Terraform rules, the \*\*single highest-leverage fix\*\* is enforcing least-privilege IAM policies at the module level. Rules CKV\_AWS\_289, CKV\_AWS\_355, CKV\_AWS\_288, and CKV\_AWS\_290 all fire because `iam.tf` contains policies with `Action = "\*"` and `Resource = "\*"`. If the IAM module enforced a policy template that requires explicit actions and scoped resources (e.g., using AWS managed policies or customer-managed policies with specific ARNs), all 14+ IAM-related findings would vanish with one architectural change. Similarly, adding a default `aws\_s3\_bucket\_public\_access\_block` resource to the S3 module with all four block flags set to `true` would eliminate CKV\_AWS\_53/54/55/56 across all buckets.



\---



\## Task 2: KICS on Ansible + Pulumi



\### KICS Ansible Severity breakdown

| Severity | Count |

|----------|------:|

| CRITICAL | 0 |

| HIGH | 9 |

| MEDIUM | 0 |

| LOW | 1 |

| INFO | 0 |

| \*\*Total\*\* | \*\*10\*\* |



\### Top 5 KICS queries (Ansible, by frequency)

| Query | Severity | Files |

|-------|----------|------:|

| Passwords And Secrets - Generic Password | HIGH | 6 |

| Passwords And Secrets - Password in URL | HIGH | 2 |

| Passwords And Secrets - Generic Secret | HIGH | 1 |

| Unpinned Package Version | LOW | 1 |



\### KICS Pulumi Severity breakdown

| Severity | Count |

|----------|------:|

| CRITICAL | 1 (RDS publicly accessible) |

| HIGH | 2 (DynamoDB not encrypted, hardcoded password) |

| MEDIUM | 1 (EC2 monitoring disabled) |

| LOW | 0 |

| INFO | 2 |

| \*\*Total\*\* | \*\*6\*\* |



\### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

\- \*\*One thing Checkov did better for Terraform:\*\* Checkov natively understands Terraform's graph model and caught cross-resource misconfigurations like `CKV2\_AWS\_5` (security groups not attached to any resource) and `CKV2\_AWS\_6` (S3 bucket without public access block). These graph-based checks require understanding relationships between resources, which KICS cannot do because it scans files statically.

\- \*\*One thing KICS did better for Ansible:\*\* KICS uses Rego queries that are format-agnostic and accurately parsed the Ansible playbook structure, flagging Linux hardening gaps like hardcoded passwords in `inventory.ini` and `configure.yml`. Checkov's Ansible support is limited to cloud modules, not OS configuration playbooks.

\- \*\*Example of single-tool catch:\*\* Checkov flagged `CKV\_SECRET\_2` (AWS Access Key) in `main.tf` because it runs a dedicated secrets engine with pattern matching for AWS key formats (`AKIA...`). KICS skipped it because KICS focuses on infrastructure misconfiguration queries, not secret pattern detection.



\---



\## Bonus: Custom Checkov Policy



\### Policy file (`labs/lab6/policies/custom\_checks/rds\_deletion\_protection.py`)

```python

from checkov.common.models.enums import CheckResult, CheckCategories

from checkov.terraform.checks.resource.base\_resource\_check import BaseResourceCheck



class RDSDeletionProtection(BaseResourceCheck):

&#x20;   def \_\_init\_\_(self):

&#x20;       name = "Ensure RDS instances have deletion\_protection enabled"

&#x20;       id = "CKV\_CUSTOM\_1"

&#x20;       supported\_resources = \['aws\_db\_instance']

&#x20;       categories = \[CheckCategories.GENERAL\_SECURITY]

&#x20;       super().\_\_init\_\_(name=name, id=id, categories=categories, supported\_resources=supported\_resources)



&#x20;   def scan\_resource\_conf(self, conf):

&#x20;       if 'deletion\_protection' in conf:

&#x20;           if conf\['deletion\_protection']\[0] == True:

&#x20;               return CheckResult.PASSED

&#x20;       return CheckResult.FAILED



check = RDSDeletionProtection()

```



\### Rule fires (Proof)

The custom policy successfully fired on both RDS instances in `database.tf`:

```json

{

&#x20; "check\_id": "CKV\_CUSTOM\_1",

&#x20; "check\_name": "Ensure RDS instances have deletion\_protection enabled",

&#x20; "check\_result": { "result": "FAILED" },

&#x20; "resource": "aws\_db\_instance.unencrypted\_db",

&#x20; "file\_path": "\\\\database.tf"

}

{

&#x20; "check\_id": "CKV\_CUSTOM\_1",

&#x20; "check\_name": "Ensure RDS instances have deletion\_protection enabled",

&#x20; "check\_result": { "result": "FAILED" },

&#x20; "resource": "aws\_db\_instance.weak\_db",

&#x20; "file\_path": "\\\\database.tf"

}

```



\### Why this rule matters

Accidental database deletion causes catastrophic data loss and downtime. The 2021 GitLab outage (caused by accidental `rm -rf`) and multiple AWS RDS incidents highlight that `deletion\_protection = true` is a critical safety net against human error or compromised CI/CD pipelines. This aligns with CIS AWS Foundations Benchmark v1.5.0 (Section 2.3.1) and NIST SP 800-144 requirement for data integrity safeguards. Enforcing it via Policy-as-Code guarantees no RDS instance reaches production without this guardrail.

