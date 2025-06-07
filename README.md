# AWS Security Audit CLI Tool

## Project Summary

This is a lightweight Python CLI tool that performs a **basic AWS security audit** using the Boto3 SDK. It checks for common misconfigurations like:

- Public S3 buckets
- Overly permissive IAM policies
- EC2 instances with public IPs
- Security groups exposing all ports to the world

This tool is designed to help DevOps engineers and cloud administrators **quickly identify risks** in their AWS environment.

---

## Tech Stack

- Python 3
- Boto3 (AWS SDK for Python)
- argparse for CLI
- AWS IAM credentials (via profile or environment variables)

---

## Features & Checks

| Check | Description |
|-------|-------------|
| S3 Buckets | Flags buckets with public access |
| IAM Policies | Detects wildcard permissions in IAM roles & policies |
| EC2 Public IPs | Lists instances exposed to the public internet |
| Security Groups | Identifies `0.0.0.0/0` rules in SGs (unrestricted access) |

---

## Usage

```bash
# Install dependencies
pip install -r requirements.txt
```

# Run the audit
```
python3 audit/audit.py --region us-east-1
```
---

## Optional Flags
```
--profile <name>     # Use specific AWS CLI profile
--region <region>    # AWS region to audit (default: us-east-1)
```
---

### Permissions Required

Make sure the IAM role or user running the script has:

- s3:ListBuckets
- iam:ListRoles, iam:GetRolePolicy
- ec2:DescribeInstances
- ec2:DescribeSecurityGroups

