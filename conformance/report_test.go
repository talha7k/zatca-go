// Parser table tests — pinned on the REVERSE-ENGINEERED SDK 3.0.8 output
// format (verbatim captured samples from the TS harness's
// parse-validation-report.test.ts discipline). Do not "fix" the parser
// against assumptions; re-capture real output if the SDK version changes.
package conformance

import (
	"reflect"
	"strings"
	"testing"
)

const stageLines = `2026-09-13 22:41:24,814 [INFO] ValidationProcessorImpl - [XSD] validation result : PASSED
2026-09-13 22:41:24,900 [INFO] ValidationProcessorImpl - [EN] validation result : PASSED
2026-09-13 22:41:25,400 [INFO] ValidationProcessorImpl - [KSA] validation result : PASSED
2026-09-13 22:41:25,502 [INFO] InvoiceValidationService -  *** GLOBAL VALIDATION RESULT = PASSED`

func TestParseValidRun(t *testing.T) {
	report := ParseValidationReport(stageLines, "")
	if report.Crashed {
		t.Fatal("a clean PASSED run must not be flagged crashed")
	}
	if !report.GloballyPassed() {
		t.Errorf("GloballyPassed = false, report=%s", report.Describe())
	}
	want := map[string]string{"XSD": "PASSED", "EN": "PASSED", "KSA": "PASSED"}
	if !reflect.DeepEqual(report.StageResults, want) {
		t.Errorf("stage results = %v, want %v", report.StageResults, want)
	}
	if report.Summary != "PASSED" {
		t.Errorf("summary = %q", report.Summary)
	}
	if len(report.XSDErrors)+len(report.SchematronErrors)+len(report.OtherErrors) != 0 {
		t.Error("clean run must carry no findings")
	}
}

func TestParseFailedSchematronRun(t *testing.T) {
	stdout := `2026-09-13 22:41:24,814 [INFO] ValidationProcessorImpl - [XSD] validation result : PASSED
2026-09-13 22:41:24,900 [INFO] ValidationProcessorImpl - [EN] validation result : FAILED
2026-09-13 22:41:24,900 [ERROR] ValidationProcessorImpl - en validation errors :
2026-09-13 22:41:24,901 [ERROR] ValidationProcessorImpl - CODE : BR-CO-15, MESSAGE : Payable amount is not equal to the tax inclusive amount
2026-09-13 22:41:24,902 [ERROR] ValidationProcessorImpl - CODE : BR-S-08, MESSAGE : VAT category taxable amount does not match the sum of line net amounts
2026-09-13 22:41:25,400 [INFO] ValidationProcessorImpl - [KSA] validation result : FAILED
2026-09-13 22:41:25,400 [ERROR] ValidationProcessorImpl - ksa validation errors :
2026-09-13 22:41:25,401 [ERROR] ValidationProcessorImpl - CODE : BR-KSA-09, MESSAGE : Seller address must contain additional number
2026-09-13 22:41:25,502 [ERROR] ValidationProcessorImpl - qr validation errors :
2026-09-13 22:41:25,503 [ERROR] ValidationProcessorImpl - CODE : R, MESSAGE : R value mismatch
2026-09-13 22:41:25,503 [INFO] InvoiceValidationService -  *** GLOBAL VALIDATION RESULT = FAILED`
	report := ParseValidationReport(stdout, "")
	if report.Crashed {
		t.Fatal("a FAILED-but-run validation is not a crash")
	}
	if report.GloballyPassed() {
		t.Error("GloballyPassed must be false")
	}
	want := map[string]string{"XSD": "PASSED", "EN": "FAILED", "KSA": "FAILED"}
	if !reflect.DeepEqual(report.StageResults, want) {
		t.Errorf("stage results = %v, want %v", report.StageResults, want)
	}
	wantEN := []string{
		"BR-CO-15 : Payable amount is not equal to the tax inclusive amount",
		"BR-S-08 : VAT category taxable amount does not match the sum of line net amounts",
		// EN and KSA schematron failures share the schematron bucket.
		"BR-KSA-09 : Seller address must contain additional number",
	}
	if !reflect.DeepEqual(report.SchematronErrors, wantEN) {
		t.Errorf("schematron errors = %v, want %v", report.SchematronErrors, wantEN)
	}
	wantOther := []string{"R : R value mismatch"}
	if !reflect.DeepEqual(report.OtherErrors, wantOther) {
		t.Errorf("other errors = %v, want %v", report.OtherErrors, wantOther)
	}
	if len(report.XSDErrors) != 0 {
		t.Errorf("xsd errors must be empty, got %v", report.XSDErrors)
	}
}

func TestParseCrashExitsZero(t *testing.T) {
	// THE TRAP: without a valid SDK_CONFIG the CLI prints this and STILL
	// exits 0. The parser must surface crashed=true.
	stdout := `2026-09-13 22:40:00,000 [ERROR] MainApp - failed to validate invoice - null`
	report := ParseValidationReport(stdout, "")
	if !report.Crashed {
		t.Fatal("crash line must set crashed=true")
	}
	if report.Summary != "" {
		t.Errorf("crashed run has no summary, got %q", report.Summary)
	}
}

func TestParseMissingSummaryIsCrash(t *testing.T) {
	// A run that printed stage lines but never reached the summary never
	// validated anything.
	stdout := `2026-09-13 22:41:24,814 [INFO] ValidationProcessorImpl - [XSD] validation result : PASSED`
	report := ParseValidationReport(stdout, "")
	if !report.Crashed {
		t.Fatal("missing summary must count as crashed")
	}
}

func TestBannerNeverParsedAsFindings(t *testing.T) {
	stdout := `***********************************
Welcome to FATOORA CLI
[ERROR] MainApp - some banner noise without timestamp
***********************************
` + stageLines
	report := ParseValidationReport(stdout, "")
	if len(report.OtherErrors)+len(report.XSDErrors)+len(report.SchematronErrors) != 0 {
		t.Errorf("banner lines leaked as findings: %s", report.Describe())
	}
	if !report.GloballyPassed() {
		t.Errorf("banner must not break the parse: %s", report.Describe())
	}
}

func TestStderrWarningsCollected(t *testing.T) {
	stderr := "2026-09-13 22:41:20,000 [WARN] SomeLogger - JVM warning noise\nplain JVM noise"
	report := ParseValidationReport(stageLines, stderr)
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "JVM warning noise") {
		t.Errorf("warnings = %v, want the single WARN line", report.Warnings)
	}
}

func TestXSDFailedStage(t *testing.T) {
	stdout := `2026-09-13 22:41:24,814 [INFO] ValidationProcessorImpl - [XSD] validation result : FAILED
2026-09-13 22:41:24,815 [ERROR] ValidationProcessorImpl - xsd validation errors :
2026-09-13 22:41:24,816 [ERROR] ValidationProcessorImpl - CODE : cvc-datatype-valid.1.2.1, MESSAGE : 'NOT-A-DATE' is not a valid value for 'date'
2026-09-13 22:41:25,503 [INFO] InvoiceValidationService -  *** GLOBAL VALIDATION RESULT = FAILED`
	report := ParseValidationReport(stdout, "")
	if len(report.XSDErrors) != 1 || !strings.Contains(report.XSDErrors[0], "NOT-A-DATE") {
		t.Errorf("xsd errors = %v", report.XSDErrors)
	}
	if report.StageResults["XSD"] != "FAILED" {
		t.Errorf("XSD stage = %q", report.StageResults["XSD"])
	}
}

func TestDescribeShape(t *testing.T) {
	report := ParseValidationReport(stageLines, "")
	description := report.Describe()
	if !strings.Contains(description, "XSD=PASSED") || !strings.Contains(description, "global=PASSED") {
		t.Errorf("Describe() = %q", description)
	}
}
