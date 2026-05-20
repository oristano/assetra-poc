package domain

// OCSFFinding is a normalized OCSF Vulnerability Finding record (class_uid 2004).
// Every field is a flat, queryable column — customers should never need to parse Raw.
// ResourceDetails holds asset-type-specific attributes so the schema stays stable
// as new asset types (RDS, Lambda, …) are added.
type OCSFFinding struct {
	ID          string
	CustomerID  string
	AccountID   string
	ClassUID    int // 2004
	SeverityID  int // OCSF: 1=Informational … 5=Critical
	Severity    string
	StatusID    int // OCSF: 1=New, 2=Suppressed, 4=Resolved
	Status      string
	Region      string

	// Finding identity
	FindingUID  string // source finding ARN — globally unique
	Title       string
	Description string

	// Resource (asset)
	ResourceUID     string
	ProviderUID     string // cloud provider's canonical fully-qualified identifier (AWS ARN, Azure Resource ID, GCP Resource Name)
	ResourceName    string
	ResourceType    string // e.g. AWS_EC2_INSTANCE, AWS_RDS_INSTANCE
	ResourceDetails string // JSON — asset-type-specific fields

	// Vulnerability
	CVEID            string
	PackageName      string
	InstalledVersion string
	FixedVersion     string

	// Timing
	FirstObservedAt string // RFC3339
	LastObservedAt  string // RFC3339
	Time            int64  // epoch ms of last_observed_at

	Raw string // full OCSF JSON document — audit trail

	// Network exposure classification
	ExposureClass      string // internal | external_restricted | external_open | unknown
	ExposureConfidence string // low | medium | high | unknown
	ExposureEvidence   string // JSON — signals used to determine the classification

	// Provenance
	Scanner         string // vulnerability scanner that produced this finding (e.g. "amazon-inspector2")
	PipelineVersion string // version of the assetra normalization code
}

// --- Reporting ---

// AssetSummary is used by the inspect command.
type AssetSummary struct {
	ResourceUID     string
	ResourceName    string
	Region          string
	FindingCount    int
	HighestSeverity string
}

// InspectResult is the output of the inspect use case.
type InspectResult struct {
	TotalFindings int
	UniqueAssets  int
	BySeverity    map[string]int
	ByExposure    map[string]int
	Summaries     []AssetSummary
	Findings      []OCSFFinding
}

// --- Raw source types (pre-normalization, from CSV) ---

type RawEC2Instance struct {
	InstanceID   string
	Name         string
	State        string
	InstanceType string
	PrivateIP    string
	PublicIP     string
	Platform     string
	Region       string
	AccountID    string
	TagsJSON     string
}

type RawInspectorFinding struct {
	FindingARN       string
	AWSAccountID     string
	ResourceID       string
	ResourceType     string
	FindingType      string
	Severity         string
	Status           string
	Title            string
	Description      string
	CVEID            string
	PackageName      string
	InstalledVersion string
	FixedVersion     string
	FirstObservedAt  string // RFC3339
	LastObservedAt   string // RFC3339
}
