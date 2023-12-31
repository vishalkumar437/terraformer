// Copyright 2020 The Terraformer Authors.
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

	"github.com/GoogleCloudPlatform/terraformer/terraformutils"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
)

var codebuildAllowEmptyValues = []string{"tags."}

type CodeBuildGenerator struct {
	AWSService
}

func (g *CodeBuildGenerator) InitResources() error {
	config, e := g.generateConfig()
	if e != nil {
		return e
	}
	svc := codebuild.NewFromConfig(config)
	p := codebuild.NewListProjectsPaginator(svc, &codebuild.ListProjectsInput{})
	for p.HasMorePages() {
		page, e := p.NextPage(context.TODO())
		if e != nil {
			return e
		}
		for _, project := range page.Projects {
			g.Resources = append(g.Resources, terraformutils.NewSimpleResource(
				project,
				project,
				"aws_codebuild_project",
				"aws",
				codebuildAllowEmptyValues))
		}
	}
	return nil
}

func (g *CodeBuildGenerator) PostConvertHook() error {
	for _, r := range g.Resources {
		if r.InstanceInfo.Type != "aws_codebuild_project" {
			continue
		}
		if r.InstanceState.Attributes["concurrent_build_limit"] == "0" {
			delete(r.Item, "concurrent_build_limit")
		}
	}
	return nil
}
