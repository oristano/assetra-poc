package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/assetra/assetra-poc/internal/domain"
)

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func prettyJSON(s string) string {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil || v == nil {
		return s
	}
	b, err := json.MarshalIndent(v, "                   ", "  ")
	if err != nil {
		return s
	}
	return string(b)
}

func printInspectResult(customerID string, result domain.InspectResult) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║              ASSETRA  —  OCSF Findings               ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("  Customer ID:     %s\n", customerID)
	fmt.Printf("  Total Findings:  %d\n", result.TotalFindings)
	fmt.Printf("  Unique Assets:   %d\n", result.UniqueAssets)

	if len(result.BySeverity) > 0 {
		fmt.Println()
		fmt.Println("  By Severity:")
		for _, sev := range []string{"Critical", "High", "Medium", "Low", "Informational", "Unknown"} {
			if cnt, ok := result.BySeverity[sev]; ok {
				fmt.Printf("    %-15s %d\n", sev+":", cnt)
			}
		}
	}

	if len(result.ByExposure) > 0 {
		fmt.Println()
		fmt.Println("  By Exposure:")
		for _, cls := range []string{"external_open", "external_restricted", "internal", "unknown"} {
			if cnt, ok := result.ByExposure[cls]; ok {
				fmt.Printf("    %-22s %d\n", cls+":", cnt)
			}
		}
	}

	if len(result.Summaries) == 0 {
		fmt.Println("\n  No findings stored.")
		return
	}

	fmt.Println()
	fmt.Println("  Asset Summary:")
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  INSTANCE ID\tNAME\tREGION\tFINDINGS\tHIGHEST SEVERITY")
	fmt.Fprintln(w, "  ───────────\t────\t──────\t────────\t────────────────")
	for _, s := range result.Summaries {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%d\t%s\n",
			s.ResourceUID, s.ResourceName, s.Region, s.FindingCount, s.HighestSeverity)
	}
	w.Flush()

	for i, f := range result.Findings {
		fmt.Println()
		fmt.Printf("  ── Finding %d of %d ────────────────────────────────────\n", i+1, len(result.Findings))
		fmt.Println()

		field := func(label, value string) {
			fmt.Printf("  %-20s %s\n", label+":", value)
		}

		field("ID", f.ID)
		field("Customer ID", f.CustomerID)
		field("Account ID", f.AccountID)
		field("Class UID", fmt.Sprintf("%d (Vulnerability Finding)", f.ClassUID))
		fmt.Println()
		field("Severity", fmt.Sprintf("%s (id=%d)", f.Severity, f.SeverityID))
		field("Status", fmt.Sprintf("%s (id=%d)", f.Status, f.StatusID))
		field("Region", f.Region)
		fmt.Println()
		field("Finding UID", f.FindingUID)
		field("Title", f.Title)
		field("Description", truncate(f.Description, 80))
		fmt.Println()
		field("Resource ID", f.ResourceUID)
		field("Provider UID", f.ProviderUID)
		field("Resource Name", f.ResourceName)
		field("Resource Type", f.ResourceType)
		field("Resource Details", prettyJSON(f.ResourceDetails))
		fmt.Println()
		field("CVE ID", f.CVEID)
		field("Package", f.PackageName)
		field("Installed Version", f.InstalledVersion)
		field("Fixed Version", f.FixedVersion)
		fmt.Println()
		field("First Observed", f.FirstObservedAt)
		field("Last Observed", f.LastObservedAt)
		fmt.Println()
		field("Exposure Class", f.ExposureClass)
		field("Exposure Confidence", f.ExposureConfidence)
		field("Exposure Evidence", prettyJSON(f.ExposureEvidence))
		fmt.Println()
		field("Scanner", f.Scanner)
		field("Pipeline Version", f.PipelineVersion)
	}

	fmt.Println()
}
