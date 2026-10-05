// Package conformance is a TEST-ONLY harness: it validates this library's
// invoice XML against the OFFICIAL ZATCA E-Invoicing Java SDK (the offline
// Compliance & Enablement Toolbox). It is never imported by production code.
//
// The mechanics are a Go port of the TypeScript harness
// (github.com/talha7k/zatca tests/conformance/{zatca-sdk.test.ts,
// validation-report.ts}) — the mechanics, never the test code.
//
// Setup (the 160MB SDK jar is NEVER committed):
//
//  1. Download the SDK from https://zatca.gov.sa (Systems Developers →
//     Compliance Enablement Toolbox → Download SDK) after accepting the
//     terms, or set ZATCA_SDK_HOME to an extracted SDK directory.
//  2. Unzip it into the repo root (e.g. zatca-envoice-sdk-203/) — the
//     harness auto-discovers zatca-*sdk* directories containing Apps/ —
//     or export ZATCA_SDK_HOME=<SDK root containing Apps/>.
//  3. A JDK is required (verified working on Java 21).
//
// SDK_CONFIG bootstrap: the SDK library locates its XSD/schematron data via
// the SDK_CONFIG environment variable (com/zatca/config/Config reads
// System.getenv("SDK_CONFIG") — there is NO fallback). Without it the CLI
// prints "failed to validate invoice - null" and exits 0 WITHOUT validating
// anything. The harness therefore writes a config with ABSOLUTE paths into a
// temp dir (never committed) and exports SDK_CONFIG for every CLI
// invocation. The SDK's shipped Configuration/config.json uses Windows
// (D:\…) paths and cannot be used on macOS/Linux.
//
// CLI facts established by reverse-engineering (see ReportParser): the
// -validate command ALWAYS exits 0, even when the global validation result
// is FAILED — gates must parse the report, never trust the exit code.
package conformance

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidationStage is a validation stage name reported by the CLI
// (observed: XSD, EN, KSA, QR; the binary also knows SIGNATURE/PIH).
type ValidationStage = string

// StageResult is PASSED or FAILED.
type StageResult = string

// ParsedValidationReport is the structured result of one SDK -validate run.
type ParsedValidationReport struct {
	// XSDErrors — structural (XML Schema) errors, entries "CODE : MESSAGE".
	XSDErrors []string
	// SchematronErrors — EN16931 + ZATCA(KSA) schematron failed-asserts,
	// entries "CODE : MESSAGE".
	SchematronErrors []string
	// Warnings — [WARN]-level log lines (SDK 3.0.8 emits none in practice).
	Warnings []string
	// OtherErrors — errors from later cryptographic stages (QR, SIGNATURE,
	// PIH), if reached.
	OtherErrors []string
	// StageResults — "PASSED"|"FAILED" per observed stage,
	// e.g. {"XSD": "PASSED", "KSA": "FAILED"}.
	StageResults map[ValidationStage]StageResult
	// Summary — the final "GLOBAL VALIDATION RESULT" value; empty when the
	// run never reached it.
	Summary StageResult
	// Crashed is true when the CLI aborted BEFORE validating (e.g. broken
	// SDK config) — a run that never reached the summary also counts.
	Crashed bool
}

var (
	logLinePattern     = regexp.MustCompile(`^(?:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) )?\[([A-Z]+)\] ([\w.$]+) - ?(.*)$`)
	stageResultPattern = regexp.MustCompile(`\[([A-Z]+)\] validation result : (PASSED|FAILED)\s*$`)
	stageErrorHeader   = regexp.MustCompile(`^(xsd|en|ksa|qr|signature|pih) validation errors : ?$`)
	codeMessagePattern = regexp.MustCompile(`^CODE : (.*?), MESSAGE : (.*)$`)
	summaryPattern     = regexp.MustCompile(`GLOBAL VALIDATION RESULT = (PASSED|FAILED)`)
	crashPattern       = regexp.MustCompile(`^failed to validate invoice(?: - (.*))?$`)
)

// bucketForStage maps a stage name (lowercase, as in the error-block header)
// to its error bucket.
func bucketForStage(stage string) string {
	switch strings.ToLower(stage) {
	case "xsd":
		return "xsd"
	case "en", "ksa":
		return "schematron"
	default:
		return "other"
	}
}

// ParseValidationReport parses the combined CLI output of `fatoora
// -validate` (SDK 3.0.8 format, reverse-engineered — see the package doc).
// The welcome banner is printed via an [ERROR] MainApp- line of
// untimestamped lines — never parsed as findings. stderr may carry JVM/log
// warnings; never findings.
//
// A run whose summary was never reached and that did not crash explicitly is
// marked Crashed: it never validated anything (this is the exit-0 trap —
// without it a broken SDK_CONFIG masquerades as a passing gate).
func ParseValidationReport(stdout, stderr string) ParsedValidationReport {
	report := ParsedValidationReport{StageResults: map[ValidationStage]StageResult{}}
	// Bucket of the error-block header currently in effect; "" = not in a block.
	currentBucket := ""

	for _, line := range strings.Split(stdout, "\n") {
		m := logLinePattern.FindStringSubmatch(line)
		if m == nil {
			continue // banner / blank / continuation noise — never a finding
		}
		level, message := m[2], m[4]

		if sm := stageResultPattern.FindStringSubmatch(message); sm != nil {
			report.StageResults[sm[1]] = sm[2]
			currentBucket = ""
			continue
		}
		if hm := stageErrorHeader.FindStringSubmatch(message); hm != nil {
			currentBucket = bucketForStage(hm[1])
			continue
		}
		if sum := summaryPattern.FindStringSubmatch(message); sum != nil {
			report.Summary = sum[1]
			currentBucket = ""
			continue
		}
		if crashPattern.MatchString(message) && level == "ERROR" {
			report.Crashed = true
			currentBucket = ""
			continue
		}
		if cm := codeMessagePattern.FindStringSubmatch(message); cm != nil && currentBucket != "" {
			entry := cm[1] + " : " + cm[2]
			switch currentBucket {
			case "xsd":
				report.XSDErrors = append(report.XSDErrors, entry)
			case "schematron":
				report.SchematronErrors = append(report.SchematronErrors, entry)
			default:
				report.OtherErrors = append(report.OtherErrors, entry)
			}
			continue
		}
		if level == "WARN" {
			report.Warnings = append(report.Warnings, message)
		}
	}

	// stderr may carry JVM/log warnings; never findings.
	for _, line := range strings.Split(stderr, "\n") {
		if m := logLinePattern.FindStringSubmatch(line); m != nil && m[2] == "WARN" {
			report.Warnings = append(report.Warnings, m[4])
		}
	}

	if report.Summary == "" && !report.Crashed {
		report.Crashed = true
	}
	return report
}

// GloballyPassed reports whether the run validated and PASSED.
func (r ParsedValidationReport) GloballyPassed() bool {
	return !r.Crashed && r.Summary == "PASSED"
}

// Describe renders a one-line human digest for test logs.
func (r ParsedValidationReport) Describe() string {
	stages := make([]string, 0, len(r.StageResults))
	for stage, result := range r.StageResults {
		stages = append(stages, fmt.Sprintf("%s=%s", stage, result))
	}
	return fmt.Sprintf("stages=[%s] xsd=%d schematron=%d other=%d warnings=%d global=%s crashed=%v",
		strings.Join(stages, " "), len(r.XSDErrors), len(r.SchematronErrors),
		len(r.OtherErrors), len(r.Warnings), orNone(r.Summary), r.Crashed)
}

func orNone(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}
