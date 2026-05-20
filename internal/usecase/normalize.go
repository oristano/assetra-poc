package usecase

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/assetra/assetra-poc/internal/domain"
)

// assetraNamespace is the UUID v5 namespace for generating deterministic IDs.
var assetraNamespace = uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

func ocsfFindingID(customerID, findingUID string) string {
	return uuid.NewSHA1(assetraNamespace, []byte(customerID+":"+findingUID)).String()
}

// NormalizeToOCSF builds an OCSF Vulnerability Finding record from a correlated
// EC2 instance and Inspector2 finding pair.
func NormalizeToOCSF(
	instance domain.RawEC2Instance,
	finding domain.RawInspectorFinding,
	customerID string,
	scanner string,
	pipelineVersion string,
) domain.OCSFFinding {
	sevID, sevStr := mapSeverity(finding.Severity)
	statusID, statusStr := mapStatus(finding.Status)
	lastObservedMS := parseEpochMS(finding.LastObservedAt)
	firstObservedMS := parseEpochMS(finding.FirstObservedAt)

	raw := buildOCSFDoc(instance, finding, customerID, sevID, sevStr, statusID, statusStr, firstObservedMS, lastObservedMS)
	rawBytes, _ := json.Marshal(raw)

	resourceDetails, _ := json.Marshal(map[string]string{
		"instance_type": instance.InstanceType,
		"state":         instance.State,
		"platform":      instance.Platform,
		"private_ip":    instance.PrivateIP,
		"public_ip":     instance.PublicIP,
	})

	providerUID := "arn:aws:ec2:" + instance.Region + ":" + finding.AWSAccountID + ":instance/" + instance.InstanceID
	exposureClass, exposureConf, exposureEvidence := classifyEC2Exposure(instance)

	return domain.OCSFFinding{
		ID:          ocsfFindingID(customerID, finding.FindingARN),
		CustomerID:  customerID,
		AccountID:   finding.AWSAccountID,
		ClassUID:    2004,
		SeverityID:  sevID,
		Severity:    sevStr,
		StatusID:    statusID,
		Status:      statusStr,
		Region:      instance.Region,

		FindingUID:  finding.FindingARN,
		Title:       finding.Title,
		Description: finding.Description,

		ResourceUID:     instance.InstanceID,
		ProviderUID:     providerUID,
		ResourceName:    instance.Name,
		ResourceType:    finding.ResourceType,
		ResourceDetails: string(resourceDetails),

		CVEID:            finding.CVEID,
		PackageName:      finding.PackageName,
		InstalledVersion: finding.InstalledVersion,
		FixedVersion:     finding.FixedVersion,

		FirstObservedAt: finding.FirstObservedAt,
		LastObservedAt:  finding.LastObservedAt,
		Time:            lastObservedMS,

		Raw: string(rawBytes),

		ExposureClass:      exposureClass,
		ExposureConfidence: exposureConf,
		ExposureEvidence:   exposureEvidence,

		Scanner:         scanner,
		PipelineVersion: pipelineVersion,
	}
}

// --- OCSF document structs (internal) ---

type ocsfDoc struct {
	ClassUID        int              `json:"class_uid"`
	ClassName       string           `json:"class_name"`
	CategoryUID     int              `json:"category_uid"`
	CategoryName    string           `json:"category_name"`
	ActivityID      int              `json:"activity_id"`
	ActivityName    string           `json:"activity_name"`
	TypeUID         int              `json:"type_uid"`
	Time            int64            `json:"time"`
	SeverityID      int              `json:"severity_id"`
	Severity        string           `json:"severity"`
	StatusID        int              `json:"status_id"`
	Status          string           `json:"status"`
	Metadata        ocsfMetadata     `json:"metadata"`
	Cloud           ocsfCloud        `json:"cloud"`
	FindingInfo     ocsfFindingInfo  `json:"finding_info"`
	Vulnerabilities []ocsfVuln       `json:"vulnerabilities"`
	Resource        ocsfResource     `json:"resource"`
}

type ocsfMetadata struct {
	Version  string      `json:"version"`
	Product  ocsfProduct `json:"product"`
	Profiles []string    `json:"profiles"`
}

type ocsfProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}

type ocsfCloud struct {
	Provider string      `json:"provider"`
	Account  ocsfAccount `json:"account"`
	Region   string      `json:"region"`
}

type ocsfAccount struct {
	UID    string `json:"uid"`
	TypeID int    `json:"type_id"`
	Type   string `json:"type"`
}

type ocsfFindingInfo struct {
	UID           string `json:"uid"`
	Title         string `json:"title"`
	Desc          string `json:"desc,omitempty"`
	Type          string `json:"type,omitempty"`
	FirstSeenTime int64  `json:"first_seen_time,omitempty"`
	LastSeenTime  int64  `json:"last_seen_time,omitempty"`
}

type ocsfVuln struct {
	CVE      ocsfCVE    `json:"cve"`
	Packages []ocsfPkg  `json:"packages,omitempty"`
}

type ocsfCVE struct {
	UID string `json:"uid"`
}

type ocsfPkg struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	FixedInVersion string `json:"fixed_in_version,omitempty"`
}

type ocsfResource struct {
	UID            string      `json:"uid"`
	Name           string      `json:"name,omitempty"`
	Type           string      `json:"type"`
	Region         string      `json:"region,omitempty"`
	CloudPartition string      `json:"cloud_partition,omitempty"`
	Namespace      string      `json:"namespace,omitempty"`
	Labels         []ocsfLabel `json:"labels,omitempty"`
}

type ocsfLabel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func buildOCSFDoc(
	inst domain.RawEC2Instance,
	f domain.RawInspectorFinding,
	customerID string,
	sevID int, sevStr string,
	statusID int, statusStr string,
	firstMS, lastMS int64,
) ocsfDoc {
	labels := parseTags(inst.TagsJSON)
	// always tag customer
	labels = append(labels, ocsfLabel{Key: "customer_id", Value: customerID})

	doc := ocsfDoc{
		ClassUID:     2004,
		ClassName:    "Vulnerability Finding",
		CategoryUID:  2,
		CategoryName: "Findings",
		ActivityID:   1,
		ActivityName: "Create",
		TypeUID:      200401,
		Time:         lastMS,
		SeverityID:   sevID,
		Severity:     sevStr,
		StatusID:     statusID,
		Status:       statusStr,
		Metadata: ocsfMetadata{
			Version:  "1.0.0",
			Profiles: []string{"cloud"},
			Product: ocsfProduct{
				Name:       "Amazon Inspector",
				VendorName: "AWS",
				Version:    "2",
			},
		},
		Cloud: ocsfCloud{
			Provider: "AWS",
			Region:   inst.Region,
			Account: ocsfAccount{
				UID:    f.AWSAccountID,
				TypeID: 10,
				Type:   "AWS Account",
			},
		},
		FindingInfo: ocsfFindingInfo{
			UID:           f.FindingARN,
			Title:         f.Title,
			Desc:          f.Description,
			Type:          f.FindingType,
			FirstSeenTime: firstMS,
			LastSeenTime:  lastMS,
		},
		Resource: ocsfResource{
			UID:            inst.InstanceID,
			Name:           inst.Name,
			Type:           "AWS::EC2::Instance",
			Region:         inst.Region,
			CloudPartition: "aws",
			Namespace:      f.AWSAccountID,
			Labels:         labels,
		},
	}

	if f.CVEID != "" || f.PackageName != "" {
		vuln := ocsfVuln{
			CVE: ocsfCVE{UID: f.CVEID},
		}
		if f.PackageName != "" {
			vuln.Packages = []ocsfPkg{{
				Name:           f.PackageName,
				Version:        f.InstalledVersion,
				FixedInVersion: f.FixedVersion,
			}}
		}
		doc.Vulnerabilities = []ocsfVuln{vuln}
	}

	return doc
}

// --- helpers ---

func mapSeverity(s string) (int, string) {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5, "Critical"
	case "HIGH":
		return 4, "High"
	case "MEDIUM":
		return 3, "Medium"
	case "LOW":
		return 2, "Low"
	case "INFORMATIONAL":
		return 1, "Informational"
	default:
		return 0, "Unknown"
	}
}

func mapStatus(s string) (int, string) {
	switch strings.ToUpper(s) {
	case "ACTIVE":
		return 1, "New"
	case "SUPPRESSED":
		return 2, "Suppressed"
	case "RESOLVED", "CLOSED":
		return 4, "Resolved"
	default:
		return 0, "Unknown"
	}
}

func parseEpochMS(ts string) int64 {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0
	}
	return t.UnixMilli()
}

// classifyEC2Exposure determines exposure class from available EC2 instance fields.
// Phase 1: public IP presence as proxy. Confidence is "low" because we lack
// security group rules and route table data to do full path evaluation.
// See docs/future_work.md §1 for Phase 2 requirements.
func classifyEC2Exposure(inst domain.RawEC2Instance) (class, confidence, evidence string) {
	hasPublicIP := inst.PublicIP != ""

	ev, _ := json.Marshal(map[string]any{
		"phase":           1,
		"has_public_ip":   hasPublicIP,
		"public_ip":       inst.PublicIP,
		"state":           inst.State,
		"missing_signals": []string{"security_group_rules", "route_table", "nacl", "subnet_type"},
	})

	if !hasPublicIP {
		return "internal", "low", string(ev)
	}
	// Has public IP but we can't check SG rules yet — assume open, flag confidence low.
	// Phase 2 will downgrade some of these to external_restricted once we have SG data.
	return "external_open", "low", string(ev)
}

// parseTags converts a tags JSON string like {"Env":"prod"} to OCSF labels.
func parseTags(tagsJSON string) []ocsfLabel {
	if tagsJSON == "" || tagsJSON == "{}" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(tagsJSON), &m); err != nil {
		return nil
	}
	labels := make([]ocsfLabel, 0, len(m))
	for k, v := range m {
		labels = append(labels, ocsfLabel{Key: k, Value: v})
	}
	return labels
}

