# Terraform Learning

Terraform learning sprint documenting practical AWS Infrastructure as Code (IaC). Progresses from basic syntax to production-ready structure—perfect showcasing S3, EC2, remote state, variables, file organization, CloudFront, and more.

## 📋 Day-by-Day Tasks

| Day | Focus | Key Learnings | Resources Created |
|-----|-------|---------------|-------------------|
| 01 | Basic Syntax + S3 | Providers, `aws_s3_bucket`, init/plan/apply | S3 bucket |
| 02 | Remote Backend | S3 backend setup, DynamoDB lock table, state migration | Remote state bucket |
| 03 | Variables + EC2 | `variables.tf`, `outputs.tf`, tfvars, `aws_instance`, lock file| EC2 instance |
| 04 | File Structure | `main.tf`, `outputs.tf`, `variables.tf`, project layout | Complete project template |
| 05 | Meta-arguments | `count` and `for_each` resource iteration | Multiple S3 buckets |
| 06 | Lifecycle Meta | `create_before_destroy`, `prevent_destroy`, SSM data source | EC2 instance |
| 07 | Expressions | Conditional, dynamic blocks, splat expressions | EC2 instances, Security Group |
| 08 | Terraform Functions | String, math, collection, and file functions in locals | S3 bucket |
| 09 | Data Sources | Fetching existing VPC, subnets, and querying AMIs | EC2 instance |
| 10 | Static Website Project | CloudFront, OAC, S3 bucket policies, `fileset` function | S3 Website + CloudFront CDN |
| 11 | VPC Peering Demo | Multi-region providers, VPC peering, Route Tables, Aliases | VPCs, EC2s, Peering Connection |
| 12 | IAM & CSV Processing | `csvdecode`, `for_each`, complex data filtering (`regex`, `can`) | IAM Users, Profiles, Groups |
| 13 | Blue-Green Deployment | Elastic Beanstalk environments, CNAME Swapping, Zero-downtime deployment | Elastic Beanstalk App, Environments |

## 🚀 Quick Start (Any Day)

```bash
cd environments/day_01  # Pick your day
terraform init
terraform plan          # Preview changes
terraform apply         # Create (type 'yes')
terraform output        # View results
terraform destroy       # Cleanup (IMPORTANT!)
```

**Prerequisites:** AWS CLI configured, Terraform installed, Free Tier account.

## 🏗️ Repository Structure

```text
terraform-learning/
├── README.md               # This file
├── environments/
│   ├── day_01/             # Basic S3 syntax, S3 bucket setup
│   ├── day_02/             # Remote state setup in S3 bucket
│   ├── day_03/             # EC2 + variables
│   ├── day_04/             # Complete file structure
│   ├── day_05/             # count and for_each meta-arguments
│   ├── day_06/             # lifecycle resource blocks
│   ├── day_07/             # Dynamic blocks and conditional expressions
│   ├── day_08/             # Built-in Terraform functions
│   ├── day_09/             # Data sources and querying AWS
│   ├── day_10/             # CloudFront + S3 Static Website project
│   ├── day_11/             # Multi-region VPC Peering Demo
│   ├── day_12/             # IAM users & groups scaling with CSV decode
│   └── day_13/             # AWS Elastic Beanstalk Blue-Green Deployment
├── screenshots/            # AWS Console proof
└── .gitignore              # Protects .terraform/, tfstate
```
