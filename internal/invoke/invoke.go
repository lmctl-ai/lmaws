// SPDX-License-Identifier: MIT

// Package invoke owns the shared lmcode host run loop: load each registered
// slot, select its result sink, run it (real or dry), complete it, and emit
// exactly one terminal envelope. Provider hosts supply cleanup, auth, memory
// watchdog and run-error hooks; the control flow stays identical across hosts.
package invoke

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/lmctl-ai/lmcode-go"
)

// Hooks are the provider-specific edges of the run loop. All are optional.
type Hooks struct {
	BeforeRun     func()
	OnRunError    func(error)
	Cleanup       func()
	AuthError     func() string
	StartWatchdog func(func(error)) func()
}

// Runner executes every registration in Results against one schema/registry.
type Runner struct {
	Results  *lmcode.InvocationResults
	Registry *lmcode.Registry
	Schema   []byte
	Contract lmcode.ResultContract
	Context  *lmcode.Context
	Hooks    Hooks
	// Order lists registration indices in execution order. Nil keeps add order.
	Order []int
	// Dry copies the invocation mode for watchdog frames emitted outside the collector.
	Dry bool
}

// Execute returns the process exit code after writing one frame.
func (r *Runner) Execute() int {
	if r.Results == nil || r.Registry == nil || r.Context == nil {
		return Failure("cli", lmcode.NewError(lmcode.CLI_USAGE, "lmcode invoke: missing runner state"))
	}
	registrations := r.Results.Registrations()
	byIndex := make(map[int]lmcode.InvocationRegistration, len(registrations))
	for _, registration := range registrations {
		byIndex[registration.Index] = registration
	}
	order := r.Order
	if len(order) == 0 {
		order = make([]int, 0, len(registrations))
		for _, registration := range registrations {
			order = append(order, registration.Index)
		}
	}
	for _, index := range order {
		registration, ok := byIndex[index]
		if !ok {
			_ = r.Results.Fail(&index, "load", lmcode.NewError(lmcode.LOAD_UNBOUND, "lmcode invoke: unknown slot index"))
			break
		}
		code, err := os.ReadFile(registration.File)
		if err != nil {
			_ = r.Results.Fail(&index, "load", lmcode.NewError(lmcode.LOAD_BAD_BYTECODE, err.Error()))
			break
		}
		program, err := lmcode.Load(code, r.Schema, r.Registry)
		if err != nil {
			_ = r.Results.Fail(&index, "load", err)
			break
		}
		if _, err := r.Results.Select(index, r.Registry, r.Contract); err != nil {
			_ = r.Results.Fail(&index, "run", err)
			break
		}

		if r.Hooks.BeforeRun != nil {
			r.Hooks.BeforeRun()
		}
		stopWatchdog := func() {}
		if r.Hooks.StartWatchdog != nil {
			stopWatchdog = r.Hooks.StartWatchdog(func(watchdogErr error) {
				if r.Hooks.OnRunError != nil {
					r.Hooks.OnRunError(watchdogErr)
				}
				r.abort(index, watchdogErr)
			})
		}
		runErr := program.Run(r.Context, r.Registry)
		if stopWatchdog != nil {
			stopWatchdog()
		}

		if r.Hooks.AuthError != nil {
			if message := r.Hooks.AuthError(); message != "" {
				r.cleanup()
				_ = r.Results.Fail(nil, "app", lmcode.NewError(lmcode.APP_FAIL, message))
				break
			}
		}
		if runErr != nil {
			r.cleanup()
			if r.Hooks.OnRunError != nil {
				r.Hooks.OnRunError(runErr)
			}
			_ = r.Results.Fail(&index, "run", runErr)
			break
		}
		if err := r.Results.Complete(index); err != nil {
			_ = r.Results.Fail(&index, "run", err)
			break
		}
	}
	return r.Results.WriteFrame(os.Stdout)
}

func (r *Runner) cleanup() {
	if r.Hooks.Cleanup != nil {
		r.Hooks.Cleanup()
	}
}

func (r *Runner) abort(index int, err error) {
	code, message := lmcode.RUN_HOST, err.Error()
	var native *lmcode.Error
	if errors.As(err, &native) {
		code, message = native.Code, native.Message
	}
	payload := `{"ok":false,"phase":"run","code":` + lmcode.JSONEscape(code) +
		`,"message":` + lmcode.JSONEscape(message)
	if len(r.Results.Registrations()) > 1 {
		payload += `,"part":` + strconv.Itoa(index)
	}
	if r.Dry {
		payload += `,"dry":true`
	}
	payload += "}"
	_, _ = fmt.Fprintf(os.Stdout, "LMCODE_RETURN_BEGIN\n%s\nLMCODE_RETURN_END\n", payload)
	os.Exit(3)
}

// Failure emits a single pre-collector failure frame and returns its exit code.
func Failure(phase string, err error) int {
	return lmcode.FailureFrame(os.Stdout, phase, err)
}
