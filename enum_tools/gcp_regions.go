package enum_tools

// AllGCPRegions is the full list from `gcloud functions regions list`.
var AllGCPRegions = []string{
	"us-central1", "us-east1", "us-east4", "us-west2", "us-west3",
	"us-west4", "europe-west1", "europe-west2", "europe-west3",
	"europe-west6", "asia-east2", "asia-northeast1", "asia-northeast2",
	"asia-northeast3", "asia-south1", "asia-southeast2",
	"northamerica-northeast1", "southamerica-east1",
	"australia-southeast1",
}

// GCPRegions is the active subset used by default (override for broader scans).
var GCPRegions = []string{"us-central1"}
