package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	lmcode "github.com/lmctl-ai/lmcode-go"

	"github.com/lmctl-ai/lmaws/internal/host"
	"github.com/lmctl-ai/lmaws/internal/invoke"
	"github.com/lmctl-ai/lmaws/internal/membudget"
	"github.com/lmctl-ai/lmaws/internal/safety"
	"github.com/lmctl-ai/lmaws/schema"
)

const Version = "0.1.27"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// Support the documented subcommand-per-schema pattern:
	//   lmaws cloud --lmcode FILE | --lmcode-schema [--json] | --lmcode-signatures [--without-std]
	// During the Go port (Phases A-C), top-level lmaws also serves the shared lmcloud schema
	// so conformance runners invoking `<host> --lmcode FILE` work directly.
	if len(args) > 0 && args[0] == "cloud" {
		args = args[1:]
	}

	if len(args) == 0 {
		printHelp(os.Stdout)
		return 0
	}

	// 1. Metadata flags (no memory budget watchdog required).
	var (
		wantVersion    bool
		wantHelp       bool
		wantNotices    bool
		wantSchema     bool
		wantSchemaJSON bool
		wantSignatures bool
		withoutStd     bool
		wantSweep      bool
		sweepArg       string
		lmcodeFiles    []string
		manifestPath   string
		endpointFlag   string
		regionFlag     string
		forceDry       bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--version" || arg == "-V":
			wantVersion = true
		case arg == "--help" || arg == "-h":
			wantHelp = true
		case arg == "--notices":
			wantNotices = true
		case arg == "--lmcode-schema":
			wantSchema = true
		case arg == "--json":
			wantSchemaJSON = true
		case arg == "--lmcode-signatures":
			wantSignatures = true
		case arg == "--without-std":
			withoutStd = true
		case arg == "--sweep":
			wantSweep = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				sweepArg = args[i]
			}
		case arg == "--dry":
			forceDry = true
		case arg == "--lmcode":
			if i+1 >= len(args) {
				return lmcode.FailureFrame(os.Stderr, "cli", lmcode.NewError(lmcode.CLI_USAGE, "--lmcode requires a bytecode path"))
			}
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				i++
				lmcodeFiles = append(lmcodeFiles, args[i])
			}
			if len(lmcodeFiles) == 0 {
				return lmcode.FailureFrame(os.Stderr, "cli", lmcode.NewError(lmcode.CLI_USAGE, "--lmcode requires a bytecode path"))
			}
		case strings.HasPrefix(arg, "--lmcode="):
			val := strings.TrimPrefix(arg, "--lmcode=")
			if val == "" {
				return lmcode.FailureFrame(os.Stderr, "cli", lmcode.NewError(lmcode.CLI_USAGE, "--lmcode requires a bytecode path"))
			}
			lmcodeFiles = append(lmcodeFiles, val)
		case arg == "--manifest":
			if i+1 >= len(args) {
				return lmcode.FailureFrame(os.Stderr, "cli", lmcode.NewError(lmcode.CLI_USAGE, "--manifest requires a file path"))
			}
			i++
			manifestPath = args[i]
		case strings.HasPrefix(arg, "--manifest="):
			manifestPath = strings.TrimPrefix(arg, "--manifest=")
			if manifestPath == "" {
				return lmcode.FailureFrame(os.Stderr, "cli", lmcode.NewError(lmcode.CLI_USAGE, "--manifest requires a file path"))
			}
		case arg == "--endpoint":
			if i+1 >= len(args) {
				return lmcode.FailureFrame(os.Stderr, "cli", lmcode.NewError(lmcode.CLI_USAGE, "--endpoint requires a URL"))
			}
			i++
			endpointFlag = args[i]
		case strings.HasPrefix(arg, "--endpoint="):
			endpointFlag = strings.TrimPrefix(arg, "--endpoint=")
		case arg == "--region":
			if i+1 >= len(args) {
				return lmcode.FailureFrame(os.Stderr, "cli", lmcode.NewError(lmcode.CLI_USAGE, "--region requires a value"))
			}
			i++
			regionFlag = args[i]
		case strings.HasPrefix(arg, "--region="):
			regionFlag = strings.TrimPrefix(arg, "--region=")
		default:
			return lmcode.FailureFrame(os.Stderr, "cli", lmcode.NewError(lmcode.CLI_USAGE, fmt.Sprintf("unknown option: %s", arg)))
		}
	}

	if wantVersion {
		fmt.Printf("lmaws %s\n", Version)
		return 0
	}
	if wantHelp {
		printHelp(os.Stdout)
		return 0
	}
	if wantNotices {
		printNotices(os.Stdout)
		return 0
	}
	if wantSchema {
		_ = wantSchemaJSON
		_, _ = os.Stdout.Write(schema.EmbeddedCloudSchema)
		return 0
	}
	if wantSignatures {
		var reg *lmcode.Registry
		if withoutStd {
			reg = lmcode.NewRegistryWithoutStd()
		} else {
			reg = lmcode.NewRegistry()
		}
		if err := host.Register(reg, host.New(host.Options{})); err != nil {
			return lmcode.FailureFrame(os.Stderr, "register", err)
		}
		var sigs []string
		if withoutStd {
			sigs = reg.HostSignatures()
		} else {
			sigs = reg.Signatures()
		}
		for _, s := range sigs {
			fmt.Println(s)
		}
		return 0
	}
	if wantSweep {
		return runSweep(sweepArg)
	}

	if len(lmcodeFiles) == 0 {
		return lmcode.FailureFrame(os.Stderr, "cli", lmcode.NewError(lmcode.CLI_USAGE, "missing --lmcode FILE"))
	}

	// 2. Apply memory budget and start watchdog before loading/executing bytecode.
	if _, err := membudget.InitFromEnv(); err != nil {
		return invoke.Failure("cli", lmcode.NewError(lmcode.CLI_USAGE, err.Error()))
	}

	if forceDry {
		_ = os.Setenv("LMCODE_DRY", "1")
	}

	var manifestPtr *string
	if manifestPath != "" {
		manifestPtr = &manifestPath
	}

	results, err := lmcode.InvocationResultsFromManifest(lmcodeFiles, manifestPtr)
	if err != nil {
		return invoke.Failure("cli", err)
	}
	contract, err := lmcode.ResultContractFromSchema(schema.EmbeddedCloudSchema)
	if err != nil {
		return invoke.Failure("load", err)
	}

	reg := lmcode.NewRegistry()
	ctx := lmcode.NewContext()
	ctx.SetDry(results.Dry() || forceDry)
	ledger := defaultLedger()
	h := host.New(host.Options{
		DefaultEndpoint: endpointFlag,
		Region:          regionFlag,
		Ledger:          ledger,
	})
	if err := host.Register(reg, h); err != nil {
		return invoke.Failure("load", err)
	}
	ctx.Set("cloud", h)

	runner := &invoke.Runner{
		Results:  results,
		Registry: reg,
		Schema:   schema.EmbeddedCloudSchema,
		Contract: contract,
		Context:  ctx,
		Dry:      results.Dry(),
		Hooks: invoke.Hooks{
			BeforeRun:     membudget.ResetRun,
			StartWatchdog: membudget.StartWatchdog,
		},
	}
	return runner.Execute()
}

func defaultLedger() *safety.RunLedger {
	return safety.NewRunLedger()
}

func runSweep(runID string) int {
	_ = runID
	l := defaultLedger()
	entries := l.Snapshot()
	out := map[string]any{
		"ok":      true,
		"swept":   len(entries),
		"entries": entries,
	}
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(out)
	return 0
}

func printHelp(w *os.File) {
	fmt.Fprintf(w, `lmaws %s — Go lmcode host for AWS (shared lmcloud schema, SIM/FAKE ONLY)

Usage:
  lmaws [cloud] --lmcode FILE [--manifest FILE] [--endpoint URL] [--region REGION] [--dry]
  lmaws [cloud] --lmcode-schema [--json]
  lmaws [cloud] --lmcode-signatures [--without-std]
  lmaws --sweep [RUN_ID]
  lmaws --notices
  lmaws --version | -V
  lmaws --help | -h

Subcommands:
  cloud                 Select the shared lmcloud provider-neutral schema (default in pilot).

Environment Variables:
  LMAWS_ENDPOINT              Loopback simulator endpoint URL (127.0.0.1, ::1, localhost only)
  LMAWS_REGION                AWS region for simulator signing (default: us-east-1)
  LMAWS_SIM_ACCESS_KEY_ID     Simulator access key ID (default: test)
  LMAWS_SIM_SECRET_ACCESS_KEY Simulator secret access key (default: test)
  LMAWS_MAX_MEMORY_MB         Memory ceiling in MiB (default: 4096)
`, Version)
}

func printNotices(w *os.File) {
	fmt.Fprintln(w, `lmaws Third-Party Software Notices
==================================

1. github.com/lmctl-ai/lmcode-go
   License: MIT
   Copyright (c) lmctl-ai

2. github.com/aws/aws-sdk-go-v2
   License: Apache License 2.0
   Copyright (c) Amazon.com, Inc. or its affiliates.`)
}
