// SPDX-License-Identifier: MIT

// Command lmaws serves the shared lmcloud schema for AWS. Everything
// provider-neutral comes from github.com/lmctl-ai/lmcloud/hostkit; this binary
// adds the AWS S3/SQS adapter (internal/aws), lmaws's CLI surface, and its
// memory watchdog.
package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/lmctl-ai/lmaws/internal/aws"
	"github.com/lmctl-ai/lmaws/internal/membudget"
	"github.com/lmctl-ai/lmcloud/hostkit/cloudhost"
	"github.com/lmctl-ai/lmcloud/hostkit/invoke"
	"github.com/lmctl-ai/lmcloud/schema"
)

const Version = "0.1.0"

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

func run(args []string, out io.Writer) int {
	var adapters []*aws.Adapter
	defer func() {
		for _, a := range adapters {
			_ = a.Close()
		}
	}()

	prog := cloudhost.Program{
		Name:    "lmaws",
		Version: Version,
		Schema:  schema.Bytes,
		Out:     out,
		Help:    helpText(),
		Notices: noticesText,
		Commands: map[string]func(args []string, out io.Writer) int{
			"--sweep": func(cmdArgs []string, w io.Writer) int {
				a := aws.New(nil)
				defer a.Close()
				return a.SweepCLI(context.Background(), cmdArgs, w)
			},
		},
		Init: func() error {
			_, err := membudget.InitFromEnv()
			return err
		},
		Hooks: invoke.Hooks{
			BeforeRun:     membudget.ResetRun,
			StartWatchdog: membudget.StartWatchdog,
		},
		NewConfig: func(_ bool) (cloudhost.Config, error) {
			a := aws.New(nil)
			adapters = append(adapters, a)
			return cloudhost.Config{
				Provider:  "aws",
				Store:     a,
				Queue:     a,
				Endpoints: aws.Endpoints(),
			}, nil
		},
	}
	return prog.Main(args)
}

func helpText() string {
	return fmt.Sprintf(`lmaws %s — Go lmcode host for AWS (shared lmcloud schema, built on lmcloud hostkit)

Usage:
  lmaws [cloud] [--lmcode|--first|--last] FILE ...
  lmaws [cloud] --lmcode-schema [--json]
  lmaws [cloud] --lmcode-signatures [--without-std]
  lmaws --sweep [--apply|--dry-run] [--all-stale] [RUN_ID]
  lmaws --notices | --version | -V | --help | -h

Dry runs come from the caller's invocation manifest (lmscript --dry-run).

Endpoints (validated; plain http only for loopback; see lmcloud design 02 §3.3):
  set_endpoint(service|"all", url) > LMCLOUD_<SVC>_ENDPOINT > LMAWS_<SVC>_ENDPOINT >
  LMCLOUD_ENDPOINT > LMAWS_ENDPOINT > AWS_ENDPOINT_URL_S3 / AWS_ENDPOINT_URL_SQS > AWS_ENDPOINT_URL
  No endpoint + no live opt-in: offline in-process fake.
  Loopback endpoint + no live opt-in: awssim simulator.

Live Mode (endpoint overrides forbidden):
  LMCLOUD_LIVE=1 and LMAWS_LIVE=1   Required double opt-in (Stage 1 read-only default)
  LMAWS_LIVE_MUTATE=1               Required third opt-in for Stage 2 create/delete mutations
  LMAWS_LIVE_ACCOUNT=254332045686   Required account policy value (verified via STS GetCallerIdentity)
  LMAWS_LIVE_REGION=us-east-1       Required region policy value
  LMAWS_LIVE_COST_CAP_USD           Optional cap (default: 0.05; Stage 2 ceiling: 0.25)

Simulator credentials and scope (loopback endpoints only):
  LMAWS_SIM_ACCESS_KEY_ID      SigV4 access key ID (default: test)
  LMAWS_SIM_SECRET_ACCESS_KEY  SigV4 secret access key (default: test)
  LMAWS_SIM_REGION             SigV4 region (default: us-east-1)
  LMAWS_COMPAT_STRIP_S3_XID    Strip S3 ?x-id= query param for pre-dc7b063 awssim (default: 1)

Other:
  LMAWS_MAX_MEMORY_MB          Memory ceiling in MiB (default 4096)`, Version)
}

const noticesText = `lmaws Third-Party Software Notices
==================================

1. github.com/lmctl-ai/lmcode-go
   License: MIT
   Copyright (c) lmctl-ai

2. github.com/lmctl-ai/lmcloud (hostkit)
   License: MIT
   Copyright (c) lmctl-ai

3. github.com/aws/aws-sdk-go-v2 & github.com/aws/smithy-go
   License: Apache License 2.0
   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.`
