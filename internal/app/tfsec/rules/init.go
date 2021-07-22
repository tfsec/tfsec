package rules

import (
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/apigateway"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/athena"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/autoscaling"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/cloudfront"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/cloudtrail"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/cloudwatch"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/codebuild"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/config"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/dynamodb"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/ec2"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/ecr"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/ecs"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/efs"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/eks"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/elasticache"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/elasticsearch"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/elasticservice"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/elb"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/elbv2"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/iam"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/kinesis"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/kms"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/lambda"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/misc"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/msk"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/rds"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/redshift"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/s3"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/sns"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/sqs"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/ssm"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/vpc"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/aws/workspace"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/azure/appservice"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/azure/compute"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/azure/container"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/azure/database"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/azure/datafactory"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/azure/datalake"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/azure/keyvault"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/azure/network"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/azure/securitycenter"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/azure/storage"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/azure/synapse"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/digitalocean/compute"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/digitalocean/droplet"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/digitalocean/loadbalancing"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/digitalocean/spaces"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/general/secrets"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/github/repositories"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/google/compute"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/google/gke"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/google/iam"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/google/storage"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/openstack/compute"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/openstack/fw"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules/oracle/compute"
)
