// SDK discovery, SDK_CONFIG bootstrap and CLI invocation — the Go port of
// the TS harness mechanics (findSdkHome / writeSdkConfig / runSdk /
// runValidate). See the package doc for the env + layout contract.
package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// SDKConfigRelativePaths are the config paths the SDK library requires
// (Config.readResourcesPaths keys) — relative to the SDK root.
var SDKConfigRelativePaths = map[string]string{
	"xsdPath":         "Data/Schemas/xsds/UBL2.1/xsd/maindoc/UBL-Invoice-2.1.xsd",
	"enSchematron":    "Data/Rules/schematrons/CEN-EN16931-UBL.xsl",
	"zatcaSchematron": "Data/Rules/schematrons/20210819_ZATCA_E-invoice_Validation_Rules.xsl",
	"certPath":        "Data/Certificates/cert.pem",
	"privateKeyPath":  "Data/Certificates/ec-secp256k1-priv-key.pem",
	"pihPath":         "Data/PIH/pih.txt",
	"inputPath":       "Data/Input",
	"usagePathFile":   "Configuration/usage.txt",
}

// SDKConfigPassword is the well-known SDK sample keystore password.
const SDKConfigPassword = "123456789"

// DefaultCLITimeout bounds one SDK CLI invocation (JVM + schematron compile
// routinely takes 10-30s; the TS harness allowed 120s per test).
const DefaultCLITimeout = 2 * time.Minute

var cliJarPattern = regexp.MustCompile(`cli-(\d+\.\d+\.\d+)-jar-with-dependencies\.jar$`)
var sdkDirPattern = regexp.MustCompile(`(?i)^zatca-.*sdk.*\d{3}$`)

// SdkInstallation is a discovered, ready-to-use SDK.
type SdkInstallation struct {
	// Home is the SDK root (contains Apps/).
	Home string
	// CliJar is the absolute path of the cli-*-jar-with-dependencies.jar.
	CliJar string
	// Version is the CLI version parsed from the jar file name (e.g. "3.0.8").
	Version string
}

// DiscoverSDK locates the official SDK: ZATCA_SDK_HOME first (must contain
// Apps/), then zatca-*sdk* directories in repoRoot containing Apps/.
// Returns nil (with reason) when absent — callers skip LOUD, never silently.
func DiscoverSDK(repoRoot string) (*SdkInstallation, string) {
	if fromEnv := os.Getenv("ZATCA_SDK_HOME"); fromEnv != "" {
		if dirExists(filepath.Join(fromEnv, "Apps")) {
			if inst, ok := cliJarIn(fromEnv); ok {
				return inst, ""
			}
			return nil, fmt.Sprintf("ZATCA_SDK_HOME=%s has no cli-*-jar-with-dependencies.jar under Apps/", fromEnv)
		}
		return nil, fmt.Sprintf("ZATCA_SDK_HOME=%s does not contain Apps/", fromEnv)
	}
	entries, err := os.ReadDir(repoRoot)
	if err != nil {
		return nil, fmt.Sprintf("repo root unreadable: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !sdkDirPattern.MatchString(name) || !dirExists(filepath.Join(repoRoot, name, "Apps")) {
			continue
		}
		if inst, ok := cliJarIn(filepath.Join(repoRoot, name)); ok {
			return inst, ""
		}
	}
	return nil, "SDK not found (download from zatca.gov.sa, unzip into the repo root as zatca-*sdk*, or set ZATCA_SDK_HOME)"
}

func cliJarIn(sdkHome string) (*SdkInstallation, bool) {
	apps := filepath.Join(sdkHome, "Apps")
	entries, err := os.ReadDir(apps)
	if err != nil {
		return nil, false
	}
	for _, entry := range entries {
		if m := cliJarPattern.FindStringSubmatch(entry.Name()); m != nil {
			return &SdkInstallation{
				Home:    sdkHome,
				CliJar:  filepath.Join(apps, entry.Name()),
				Version: m[1],
			}, true
		}
	}
	return nil, false
}

// JavaAvailable reports whether a `java` binary exists and runs.
func JavaAvailable() bool {
	cmd := exec.Command("java", "-version")
	return cmd.Run() == nil
}

// WriteSDKConfig writes an SDK config with ABSOLUTE paths (the vendored
// config.json ships Windows paths; the defaults resolve relative to the
// SDK's Configuration/ dir and break when CWD is the repo root) into dir and
// returns the file path. dir must be a throwaway/gitignored location — use a
// t.TempDir() in tests.
func WriteSDKConfig(sdkHome, dir string) (string, error) {
	config := make(map[string]string, len(SDKConfigRelativePaths)+1)
	for key, relative := range SDKConfigRelativePaths {
		config[key] = filepath.Join(sdkHome, relative)
	}
	config["certPassword"] = SDKConfigPassword
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal sdk config: %w", err)
	}
	path := filepath.Join(dir, "sdk-config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", fmt.Errorf("write sdk config: %w", err)
	}
	return path, nil
}

// CLIRun captures one SDK CLI invocation.
type CLIRun struct {
	Args   []string
	Status int
	Stdout string
	Stderr string
}

// RunSDK invokes the CLI jar with the no-fallback SDK_CONFIG env. extraArgs
// are appended after the shared flags (--globalVersion, -certpassword).
func (inst *SdkInstallation) RunSDK(sdkConfigPath string, extraArgs ...string) (CLIRun, error) {
	return inst.RunSDKContext(context.Background(), sdkConfigPath, extraArgs...)
}

// RunSDKContext is RunSDK with a context (timeout control).
func (inst *SdkInstallation) RunSDKContext(ctx context.Context, sdkConfigPath string, extraArgs ...string) (CLIRun, error) {
	args := []string{
		"-Djdk.module.illegalAccess=deny",
		"-Djdk.sunec.disableNative=false",
		"-jar", inst.CliJar,
		"--globalVersion", inst.Version,
		"-certpassword", SDKConfigPassword,
	}
	args = append(args, extraArgs...)
	cmd := exec.CommandContext(ctx, "java", args...)
	cmd.Env = append(os.Environ(), "SDK_CONFIG="+sdkConfigPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	run := CLIRun{Args: args, Stdout: stdout.String(), Stderr: stderr.String()}
	if err == nil {
		run.Status = 0
	} else if exitErr, ok := err.(*exec.ExitError); ok {
		run.Status = exitErr.ExitCode()
	} else {
		return run, fmt.Errorf("run SDK CLI: %w", err)
	}
	return run, nil
}

// RunValidate runs `-validate -invoice <path>` and parses the report. It
// returns an ERROR when the CLI crashed before validating — a misconfigured
// machine must never masquerade as a passing gate. Note the exit-0 trap: the
// status is carried on the run but NEVER used as the verdict.
func (inst *SdkInstallation) RunValidate(ctx context.Context, sdkConfigPath, invoicePath string) (CLIRun, ParsedValidationReport, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultCLITimeout)
	defer cancel()
	run, err := inst.RunSDKContext(ctx, sdkConfigPath, "-validate", "-invoice", invoicePath)
	if err != nil {
		return run, ParsedValidationReport{}, err
	}
	report := ParseValidationReport(run.Stdout, run.Stderr)
	if report.Crashed {
		return run, report, fmt.Errorf(
			"SDK -validate crashed before validating (broken SDK install or SDK_CONFIG); "+
				"stdout tail=%q", tail(strings.TrimSpace(run.Stdout), 600))
	}
	return run, report, nil
}

// ExtractHash runs `-generateHash -invoice <path>` and returns the hash the
// SDK computed (parity oracle for our HashCanonical over the TS canonical
// form).
func (inst *SdkInstallation) ExtractHash(ctx context.Context, sdkConfigPath, invoicePath string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultCLITimeout)
	defer cancel()
	run, err := inst.RunSDKContext(ctx, sdkConfigPath, "-generateHash", "-invoice", invoicePath)
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`INVOICE HASH = (\S+)`).FindStringSubmatch(run.Stdout + run.Stderr)
	if m == nil {
		return "", fmt.Errorf("SDK did not report a hash: stdout=%q stderr=%q", tail(run.Stdout, 400), tail(run.Stderr, 400))
	}
	return m[1], nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
