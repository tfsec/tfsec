package appservice

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Provider:  provider.AzureProvider,
		Service:   "appservice",
		ShortCode: "ftp-deployments-disabled",
		Documentation: rule.RuleDocumentation{
			Summary:     "Ensure FTP Deployments are disabled",
			Explanation: `FTPS (Secure FTP) is used to enhance security for Azure web application using App Service as it adds an extra layer of security to the FTP protocol, and help you to comply with the industry standards and regulations. For enhanced security, it is highly advices to use FTP over TLS/SSL only. You can also disable both FTP and FTPS if you don't use FTP deployment.`,
			Impact:      "FTP is insecure and can lead to loss of data",
			Resolution:  "Disable FTP",
			BadExample: []string{`
resource "azurerm_app_service" "bad_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
}
`},
			GoodExample: []string{`
resource "azurerm_app_service" "good_example" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    ftps_state = "Disabled"
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#ftps_state",
				"https://docs.microsoft.com/en-us/azure/app-service/deploy-ftp",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_app_service",
		},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {

			if resourceBlock.MissingChild("site_config") {
				set.AddResult().
					WithDescription("Resource '%s' does not have site_config block", resourceBlock.FullName())
				return
			}

			siteConfig := resourceBlock.GetBlock("site_config")
			if ftpsState := siteConfig.GetAttribute("ftps_state"); ftpsState.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' uses default value for site_config.ftps_state.", resourceBlock.FullName())
				return
			} else if ftpsState.IsAny("FtpsOnly", "AllAllowed") {
				set.AddResult().
					WithDescription("Resource '%s' has an site_config.ftps_state which enables FTP/FTPS.", resourceBlock.FullName()).
					WithAttribute(ftpsState)
			} else if ftpsState.Equals("Disabled") {
				return
			} else {
				set.AddResult().
					WithDescription("Resource '%s' has a value for site_config.ftps_state that is not one of the possible values.", resourceBlock.FullName()).
					WithAttribute(ftpsState)
			}

		},
	})
}
