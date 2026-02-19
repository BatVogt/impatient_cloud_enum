package enum_tools

// AllAzureRegions is the full list from `az account list-locations`.
var AllAzureRegions = []string{
	"eastasia", "southeastasia", "centralus", "eastus", "eastus2",
	"westus", "northcentralus", "southcentralus", "northeurope",
	"westeurope", "japanwest", "japaneast", "brazilsouth",
	"australiaeast", "australiasoutheast", "southindia", "centralindia",
	"westindia", "canadacentral", "canadaeast", "uksouth", "ukwest",
	"westcentralus", "westus2", "koreacentral", "koreasouth",
	"francecentral", "francesouth", "australiacentral",
	"australiacentral2", "southafricanorth", "southafricawest",
}

// AzureRegions is the active subset used by default (override for broader scans).
var AzureRegions = []string{"eastus"}
