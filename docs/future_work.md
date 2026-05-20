# Future Work

Tracks planned improvements identified during architecture and research sessions.
Items are grouped by domain. Each item notes what data or infrastructure is required before it can be built.

---

## 1. Exposure Classification

### Phase 2 — Full path evaluation (replaces low-confidence heuristic)

**Current (Phase 1):** `public_ip != ""` → `external_open`. Confidence: `low`.

**Target:** End-to-end reachability evaluation matching AWS Network Access Analyzer's model.
Classification uses all four conditions together — not any single signal.

**Algorithm:**
1. Identify public attachment: public IP, Elastic IP, public IPv6, or external IP.
2. Determine path type: direct instance, load balancer front door, gateway, or none.
3. Evaluate effective inbound controls:
   - AWS: security group rules on instance/ENI + NACLs + route table has IGW.
   - Azure: effective NSG rules on NIC + subnet (use "effective security rules" view, not raw NSG fragments).
   - GCP: effective VPC firewall ingress rules targeting the instance.
4. Normalize source ranges: `0.0.0.0/0` or `::/0` → world-open; known-corporate CIDRs → restricted.
5. Assign class:
   - No public path → `internal`
   - Public path + narrow source ranges only → `external_restricted`
   - Public path + broad source ranges (`0.0.0.0/0`) → `external_open`
6. Persist evidence: rules used, source ranges, ports, path explanation, confidence `high`.

**Additional Steampipe tables required (AWS):**
- `aws_vpc_security_group_rule` — inbound allow/deny rules per SG
- `aws_vpc_route_table` — to confirm subnet has a route to an internet gateway
- `aws_vpc_subnet` — subnet attributes (public/private classification)
- `aws_vpc_network_acl` — subnet-level NACL rules

**Notes:**
- NAT gateway = outbound internet only → asset stays `internal` for inbound classification.
- A public subnet alone does NOT mean the instance is internet-reachable; the instance still needs a public address and permissive security posture.
- `external_restricted` requires knowing which source CIDRs count as "trusted/corporate." This is customer-specific configuration — expose as a config parameter.

---

### Phase 2b — Load balancer as exposure point

An EC2 instance may have no public IP itself but be exposed through a public-facing load balancer.
This is `external_open` via a controlled front door and should be classified differently from direct instance exposure.

**Required data:**
- `aws_ec2_load_balancer` / `aws_alb` — scheme (internet-facing vs internal), listeners, target groups
- Join: target group → registered EC2 instance

**New field:** `public_entry_point_type` — `instance_public_ip | load_balancer | gateway | none`

---

## 2. Risk Scoring

### Combine vulnerability severity with exposure class

Today we store severity and exposure independently. The product value is in the combination.

**Planned fields on `ocsf_findings`:**
- `risk_score INT` — computed score, e.g. `severity_id × exposure_weight`
- `risk_boost_reason TEXT` — human-readable explanation, e.g. `"critical_vuln_on_world_open_asset"`

**Exposure weight table (suggested):**

| exposure_class     | weight |
|--------------------|--------|
| internal           | 1      |
| external_restricted| 2      |
| external_open      | 3      |
| unknown            | 1      |

**Example:** Critical (id=5) × external_open (weight=3) = risk_score 15.

**CLI output:** Add "Top risky assets" section sorted by risk_score descending.

---

## 3. Additional Asset Types

Each new asset type needs:
1. A source reader method (in `internal/adapters/source/steampipe.go`)
2. A normalizer function (in `internal/usecase/normalize_<type>.go`)
3. Asset-type-specific exposure logic
4. `resource_details` fields specific to that type
5. Mock CSV data under `data/aws/<service>/`

### Planned asset types

| Asset type           | resource_type value       | Key exposure signal                        |
|----------------------|---------------------------|---------------------------------------------|
| RDS instance         | `AWS_RDS_INSTANCE`        | `publicly_accessible = true` flag           |
| S3 bucket            | `AWS_S3_BUCKET`           | public bucket policy or ACL                 |
| Lambda function      | `AWS_LAMBDA_FUNCTION`     | public function URL or API Gateway endpoint |
| ALB / NLB            | `AWS_ELBV2_LOAD_BALANCER` | scheme = `internet-facing`                  |
| ECS task             | `AWS_ECS_TASK`            | public IP assigned in public subnet         |
| Azure VM             | `AZURE_VM`                | NIC public IP + effective NSG inbound rules |
| GCP Compute instance | `GCP_COMPUTE_INSTANCE`    | external IP + VPC firewall ingress rules     |

---

## 4. Multi-Cloud Source Support

### Azure
- Source reader for Azure via Steampipe `azure` plugin tables
- Exposure logic: NIC/IP configuration public IP + effective NSG rules on NIC and subnet
- `provider_uid` format: `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}`

### GCP
- Source reader for GCP via Steampipe `gcp` plugin tables
- Exposure logic: external IP + VPC firewall ingress rules with `0.0.0.0/0`
- `provider_uid` format: `//compute.googleapis.com/projects/{proj}/zones/{zone}/instances/{name}`

---

## 5. Schema & Data Product Improvements

### Inspect output enhancements
- Assets grouped by exposure class with counts
- "World-open assets with Critical/High findings" section — highest-priority view
- Findings sorted by risk_score (not just severity_id)

### Pagination / filtering
- `--severity` flag on `inspect` command
- `--exposure` flag to filter by exposure class
- `--limit` to cap finding output

### Export
- `--format json` flag on `inspect` to emit the full `ocsf_findings` table as NDJSON
- Enables downstream ingestion into SIEMs, dashboards, etc.

---

## 6. Pipeline Improvements

### Incremental ingest
- Currently full re-ingest every run (upsert handles idempotency).
- Add `--since` flag: only process findings updated after a timestamp.
- Requires `last_seen_at` watermark tracking.

### Multi-customer support
- `customer_id` is already a column and all queries are scoped by it.
- Pipeline command should accept `--customer-id` flag (currently hardcoded from env).
- Long-term: loop over a customer registry.

### Ingest audit log
- Record each pipeline run: start time, end time, records upserted, unmatched count, pipeline version.
- Enables debugging and customer-facing transparency ("last scanned at…").
