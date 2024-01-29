// Copyright 2018 The Terraformer Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aws

import (
	"context"
	"fmt"
	"log"

	"github.com/GoogleCloudPlatform/terraformer/terraformutils"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var S3AllowEmptyValues = []string{"tags."}

var S3AdditionalFields = map[string]interface{}{}

type S3Generator struct {
	AWSService
}

// createResources iterate on all buckets
// for each bucket we check region and choose only bucket from set region
// for each bucket try get bucket policy, if policy exist create additional NewTerraformResource for policy
func (g *S3Generator) createResources(config aws.Config, buckets *s3.ListBucketsOutput, region string) []terraformutils.Resource {
	var resources []terraformutils.Resource
	svc := s3.NewFromConfig(config)
	for _, bucket := range buckets.Buckets {
		resourceName := StringValue(bucket.Name)
		location, err := svc.GetBucketLocation(context.TODO(), &s3.GetBucketLocationInput{Bucket: bucket.Name})
		if err != nil {
			log.Println(err)
			continue
		}
		// check if bucket in region
		constraintString := string(location.LocationConstraint)
		if constraintString == region || (constraintString == "" && region == "us-east-1") {
			attributes := map[string]string{
				"force_destroy": "false",
				"acl":           "private",
			}
			// Check if public access block exists for the bucket
			publicAccessBlock, err := svc.GetPublicAccessBlock(context.TODO(), &s3.GetPublicAccessBlockInput{
				Bucket: bucket.Name,
			})
			if err == nil && (publicAccessBlock.PublicAccessBlockConfiguration != nil) {
				// If public access block exists, generate Terraform resource
				attributes["public_access_block"] = "true"
				resources = append(resources, terraformutils.NewResource(
					resourceName,
					resourceName,
					"aws_s3_bucket_public_access_block",
					"aws",
					nil,
					S3AllowEmptyValues,
					S3AdditionalFields))
			}

			// Check if bucket ACL exists
			bucketAcl, err := svc.GetBucketAcl(context.TODO(), &s3.GetBucketAclInput{
				Bucket: bucket.Name,
			})
			if err == nil && bucketAcl.Owner != nil {
				// If ACL exists, generate Terraform resource(requires clarification currently using DisplayName as ACL)
				attributes["acl"] = *bucketAcl.Owner.DisplayName
				resources = append(resources, terraformutils.NewResource(
					resourceName,
					resourceName,
					"aws_s3_bucket_acl",
					"aws",
					attributes,
					S3AllowEmptyValues,
					S3AdditionalFields))
			}

			// Check if bucket ownership controls exist
			ownershipControls, err := svc.GetBucketOwnershipControls(context.TODO(), &s3.GetBucketOwnershipControlsInput{
				Bucket: bucket.Name,
			})
			if err == nil && ownershipControls.OwnershipControls != nil && len(ownershipControls.OwnershipControls.Rules) > 0 {
				// If ownership controls exist, generate Terraform resource for ownership controls
				attributes["ownership_controls"] = "true"
				resources = append(resources, terraformutils.NewResource(
					resourceName,
					resourceName,
					"aws_s3_bucket_ownership_controls",
					"aws",
					nil,
					S3AllowEmptyValues,
					S3AdditionalFields))
			}

			// Check if server-side encryption configuration exists
			encryptionConfig, err := svc.GetBucketEncryption(context.TODO(), &s3.GetBucketEncryptionInput{
				Bucket: bucket.Name,
			})
			if err == nil && encryptionConfig.ServerSideEncryptionConfiguration != nil && len(encryptionConfig.ServerSideEncryptionConfiguration.Rules) > 0 {
				// If encryption configuration exists, generate Terraform resource for encryption configuration
				attributes["server_side_encryption_configuration"] = "true"
				resources = append(resources, terraformutils.NewResource(
					resourceName,
					resourceName,
					"aws_s3_bucket_server_side_encryption_configuration",
					"aws",
					nil,
					S3AllowEmptyValues,
					S3AdditionalFields))
			}

			// Check if versioning configuration exists
			versioningConfig, err := svc.GetBucketVersioning(context.TODO(), &s3.GetBucketVersioningInput{
				Bucket: bucket.Name,
			})
			if err == nil && versioningConfig.Status != "" {
				// If versioning configuration exists, generate Terraform resource for versioning
				attributes["versioning"] = "true"
				resources = append(resources, terraformutils.NewResource(
					resourceName,
					resourceName,
					"aws_s3_bucket_versioning",
					"aws",
					nil,
					S3AllowEmptyValues,
					S3AdditionalFields))
			}

			// Check if replication configuration exists
			replicationConfig, err := svc.GetBucketReplication(context.TODO(), &s3.GetBucketReplicationInput{
				Bucket: bucket.Name,
			})
			if err == nil && replicationConfig.ReplicationConfiguration != nil {
				// If replication configuration exists, generate Terraform resource for replication configuration
				attributes["replication_configuration"] = "true"
				resources = append(resources, terraformutils.NewResource(
					resourceName,
					resourceName,
					"aws_s3_bucket_replication_configuration",
					"aws",
					nil,
					S3AllowEmptyValues,
					S3AdditionalFields))
			}

			// Check if lifecycle configuration exists
			lifecycleConfig, err := svc.GetBucketLifecycleConfiguration(context.TODO(), &s3.GetBucketLifecycleConfigurationInput{
				Bucket: bucket.Name,
			})
			if err == nil && lifecycleConfig.Rules != nil && len(lifecycleConfig.Rules) > 0 {
				// If lifecycle configuration exists, generate Terraform resource for lifecycle configuration
				attributes["lifecycle_configuration"] = "true"
				resources = append(resources, terraformutils.NewResource(
					resourceName,
					resourceName,
					"aws_s3_bucket_lifecycle_configuration",
					"aws",
					nil,
					S3AllowEmptyValues,
					S3AdditionalFields))
			}

			// try get policy
			var policy *s3.GetBucketPolicyOutput
			policy, err = svc.GetBucketPolicy(context.TODO(), &s3.GetBucketPolicyInput{
				Bucket: bucket.Name,
			})

			if err == nil && policy.Policy != nil {
				attributes["policy"] = *policy.Policy
				resources = append(resources, terraformutils.NewResource(
					resourceName,
					resourceName,
					"aws_s3_bucket_policy",
					"aws",
					nil,
					S3AllowEmptyValues,
					S3AdditionalFields))
			}
			resources = append(resources, terraformutils.NewResource(
				resourceName,
				resourceName,
				"aws_s3_bucket",
				"aws",
				attributes,
				S3AllowEmptyValues,
				S3AdditionalFields))
		}
	}
	return resources
}

// Generate TerraformResources from AWS API,
// Need bucket name as ID for terraform resource
func (g *S3Generator) InitResources() error {
	config, e := g.generateConfig()
	if e != nil {
		return e
	}
	svc := s3.NewFromConfig(config)

	buckets, err := svc.ListBuckets(context.TODO(), nil)
	if err != nil {
		return err
	}
	g.Resources = g.createResources(config, buckets, g.GetArgs()["region"].(string))
	return nil
}

// PostGenerateHook for add bucket policy json as heredoc
// support only bucket with policy
func (g *S3Generator) PostConvertHook() error {
	for i, resource := range g.Resources {
		if resource.InstanceInfo.Type == "aws_s3_bucket" {
			if val, ok := g.Resources[i].Item["acl"]; ok && val == "private" {
				delete(g.Resources[i].Item, "acl")
			}
			if val, ok := g.Resources[i].Item["policy"]; ok {
				g.Resources[i].Item["policy"] = fmt.Sprintf(`<<POLICY
%s
POLICY`, g.escapeAwsInterpolation(val.(string)))
			}
		}
	}
	return nil
}
