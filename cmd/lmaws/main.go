// SPDX-License-Identifier: MIT

// Command lmaws serves the shared lmcloud schema for AWS. Everything
// provider-neutral comes from github.com/lmctl-ai/lmcloud/hostkit; this binary
// adds the AWS S3/SQS adapter (internal/aws), lmaws's CLI surface, and its
// memory watchdog.
package main

import (
	"fmt"
	"io"
	"os"

	lmcode "github.com/lmctl-ai/lmcode-go"

	"github.com/lmctl-ai/lmaws/internal/aws"
	"github.com/lmctl-ai/lmaws/internal/membudget"
	"github.com/lmctl-ai/lmcloud/hostkit/cloudhost"
	"github.com/lmctl-ai/lmcloud/hostkit/invoke"
	"github.com/lmctl-ai/lmcloud/schema"
)

const Version = "0.1.0"

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

func run(args []string, out io.Writer) int {
	// `lmaws cloud ...` selects the shared schema (the only schema served in Phase A-C).
	if len(args) > 0 && args[0] == "cloud" {
		args = args[1:]
	}

	// Support explicit `--dry` flag in addition to LMCODE_INVOCATION_FILE.
	forceDry := false
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--dry" {
			forceDry = true
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered

	switch {
	case len(args) == 0 || (len(args) == 1 && (args[0] == "--help" || args[0] == "-h")):
		printHelp(out)
		return 0
	case len(args) == 1 && (args[0] == "--version" || args[0] == "-V"):
		fmt.Fprintf(out, "lmaws %s\n", Version)
		return 0
	case len(args) == 1 && args[0] == "--notices":
		printNotices(out)
		return 0
	case len(args) >= 1 && args[0] == "--sweep":
		fmt.Fprintln(out, `{"ok":true,"swept":0,"mode":"sim-or-fake-only"}`)
		return 0
	case args[0] == "--lmcode-schema" && (len(args) == 1 || (len(args) == 2 && args[1] == "--json")):
		_, _ = out.Write(schema.Bytes)
		return 0
	case args[0] == "--lmcode-signatures" && (len(args) == 1 || (len(args) == 2 && args[1] == "--without-std")):
		return signatures(out, len(args) == 2)
	case invoke.IsInvocation(args):
		return invocation(args, forceDry, out)
	}
	return invoke.Failure("cli", lmcode.NewError(lmcode.CLI_USAGE, fmt.Sprintf("unknown or malformed arguments: %q (see lmaws --help)", args)))
}

func signatures(out io.Writer, withoutStd bool) int {
	reg := lmcode.NewRegistry()
	if withoutStd {
		reg = lmcode.NewRegistryWithoutStd()
	}
	if err := cloudhost.Register(reg, io.Discard); err != nil {
		return invoke.Failure("app", lmcode.NewError(lmcode.APP_FAIL, err.Error()))
	}
	sigs := reg.Signatures()
	if withoutStd {
		sigs = reg.HostSignatures()
	}
	for _, s := range sigs {
		fmt.Fprintln(out, s)
	}
	return 0
}

// invocation mirrors cloudhost.Program.Main and adds lmaws's memory budget
// hooks (invoke.Hooks{BeforeRun, StartWatchdog}).
func invocation(args []string, forceDry bool, out io.Writer) int {
	if _, err := membudget.InitFromEnv(); err != nil {
		return invoke.Failure("cli", lmcode.NewError(lmcode.CLI_USAGE, err.Error()))
	}
	inv, err := invoke.ParseArgs(args)
	if err != nil {
		return invoke.Failure("cli", err)
	}
	if forceDry {
		inv.Dry = true
	}
	reg, err := cloudhost.NewRegistry(out)
	if err != nil {
		return invoke.Failure("app", lmcode.NewError(lmcode.APP_FAIL, err.Error()))
	}
	contract, err := lmcode.ResultContractFromSchema(schema.Bytes)
	if err != nil {
		return invoke.Failure("load", err)
	}
	adapter := aws.New(nil)
	ctx := lmcode.NewContext()
	ctx.Set("cloud", cloudhost.New(cloudhost.Config{
		Provider:  "aws",
		Store:     adapter,
		Queue:     adapter,
		Endpoints: aws.Endpoints(),
	}))
	runner := &invoke.Runner{
		Results:  inv.Results,
		Registry: reg,
		Schema:   schema.Bytes,
		Contract: contract,
		Context:  ctx,
		Order:    inv.Order,
		Dry:      inv.Dry,
		Builder:  inv.Builder,
		Out:      out,
		Hooks: invoke.Hooks{
			BeforeRun:     membudget.ResetRun,
			StartWatchdog: membudget.StartWatchdog,
		},
	}
	return runner.Execute()
}

func printHelp(w io.Writer) {
	fmt.Fprintf(w, `lmaws %s — Go lmcode host for AWS (shared lmcloud schema, built on lmcloud hostkit)

Usage:
  lmaws [cloud] [--lmcode|--first|--last] FILE ...
  lmaws [cloud] --lmcode-schema [--json]
  lmaws [cloud] --lmcode-signatures [--without-std]
  lmaws --sweep [RUN_ID]
  lmaws --notices | --version | -V | --help | -h

Dry runs come from the caller's invocation manifest (lmscript --dry-run).

Endpoints (validated; plain http only for loopback; see lmcloud design 02 §3.3):
  set_endpoint(service|"all", url) > LMCLOUD_<SVC>_ENDPOINT > LMAWS_<SVC>_ENDPOINT >
  LMCLOUD_ENDPOINT > LMAWS_ENDPOINT > AWS_ENDPOINT_URL_S3 / AWS_ENDPOINT_URL_SQS > AWS_ENDPOINT_URL
  No endpoint: offline in-process fake. LMAWS_LIVE=1 or a non-loopback endpoint:
  not supported yet (live AWS credential chain is a future phase).

Simulator credentials and scope (loopback endpoints only):
  LMAWS_SIM_ACCESS_KEY_ID      SigV4 access key ID (default: test)
  LMAWS_SIM_SECRET_ACCESS_KEY  SigV4 secret access key (default: test)
  LMAWS_SIM_REGION             SigV4 region (default: us-east-1)
  LMAWS_COMPAT_STRIP_S3_XID    Strip S3 ?x-id= query param for pre-dc7b063 awssim (default: 1)

Other:
  LMAWS_MAX_MEMORY_MB          Memory ceiling in MiB (default 4096)
`, Version)
}

func printNotices(w io.Writer) {
	fmt.Fprintln(w, `lmaws Third-Party Software Notices
==================================

1. github.com/lmctl-ai/lmcode-go
   License: MIT
   Copyright (c) lmctl-ai

2. github.com/lmctl-ai/lmcloud (hostkit)
   License: MIT
   Copyright (c) lmctl-ai

3. github.com/aws/aws-sdk-go-v2 & github.com/aws/smithy-go
   License: Apache License 2.0
   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.`)
}
