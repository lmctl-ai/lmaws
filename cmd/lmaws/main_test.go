// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lmctl-ai/lmcloud/schema"
)

func TestServedSchemaMatchesLock(t *testing.T) {
	raw, err := os.ReadFile("../../lmcloud.lock")
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := run([]string{"cloud", "--lmcode-schema", "--json"}, &out); code != 0 {
		t.Fatalf("exit %d", code)
	}
	sum := sha256.Sum256(out.Bytes())
	if got := hex.EncodeToString(sum[:]); got != lock.SHA256 || !bytes.Equal(out.Bytes(), schema.Bytes) {
		t.Fatalf("served schema sha256 %s, lmcloud.lock pins %s", got, lock.SHA256)
	}
}

func findLmscript(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("LMSCRIPT_BIN"); bin != "" {
		return bin
	}
	if bin, err := exec.LookPath("lmscript"); err == nil {
		return bin
	}
	for _, candidate := range []string{
		"/home/ubuntu/.nvm/versions/node/v24.22.0/bin/lmscript",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	t.Skip("lmscript not on PATH, skipping std REST/CLI test")
	return ""
}

func TestStdRestAndCliInterfaces(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--lmaws-std-rest-host" {
			os.Exit(run(os.Args[i+1:], os.Stdout))
		}
	}

	var sigOut bytes.Buffer
	if code := run([]string{"--lmcode-signatures"}, &sigOut); code != 0 {
		t.Fatalf("--lmcode-signatures exited %d", code)
	}
	for _, want := range []string{
		"fn rest_config(string, string) -> void",
		"fn rest_route(string, string, string) -> void",
		"fn rest_serve() -> void",
		"fn rest_stop() -> void",
		"fn rest_cli(StrList) -> string",
		"method RestExchange.param(string) -> string",
	} {
		if !strings.Contains(sigOut.String(), want) {
			t.Fatalf("missing std REST/CLI signature %q", want)
		}
	}

	bin := findLmscript(t)
	tmp := t.TempDir()
	schemaPath := filepath.Join(tmp, "lmcloud.dsl.json")
	if err := os.WriteFile(schemaPath, schema.Bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	selfBin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	lms := `
s = load_schema(schema="` + schemaPath + `");
p = _lmcode_ s;
  @"/objects/:bucket/:key"
  fn get_object(x: RestExchange) -> void implements RestGet {
    let val = cloud.object_get(x.param("bucket"), x.param("key"));
    x.send(x.get("cli_format") + ":" + val);
  }

  @"--format"
  fn opt_format(x: RestExchange) -> void implements CliOption {
    x.set("cli_format", x.query("format"));
  }

  @"inspect"
  fn cmd_inspect(x: RestExchange) -> void implements CliCommand {
    x.send("aws-cli:" + x.get("cli_format") + ":" + x.body());
  }

  rest_config("prefix", "/v1");
  cloud.bucket_create("lmaws-rest-bkt");
  cloud.object_put("lmaws-rest-bkt", "greeting.txt", "hello-aws");

  let cli_out = rest_cli(str_split("--format json inspect -- aws-ready", " "));
  let get_out = rest_cli(str_split("/v1/objects/lmaws-rest-bkt/greeting.txt", " "));
  lmcode_return_put("cli_out", cli_out);
  lmcode_return_put("get_out", get_out);
end _lmcode_
r = run_lmcode(p, {command: ["` + selfBin + `", "-test.run=^TestStdRestAndCliInterfaces$", "--", "--lmaws-std-rest-host", "--lmcode", "$DSLFILE"]});
assert(r.ok, "expected lmaws run to succeed");
assert(r.result.cli_out == "aws-cli:json:aws-ready", "unexpected cli_out: " + r.result.cli_out);
assert(r.result.get_out == "json:hello-aws", "unexpected get_out: " + r.result.get_out);
println("LMAWS_STD_REST_CLI_OK");
`
	lmsPath := filepath.Join(tmp, "rest_cli.lms")
	if err := os.WriteFile(lmsPath, []byte(lms), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, lmsPath)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "LMAWS_STD_REST_CLI_OK") {
		t.Fatalf("lmaws std rest/cli execution failed: %v\n%s", err, out)
	}
}
