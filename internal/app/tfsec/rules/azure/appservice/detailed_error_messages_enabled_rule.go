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
		ShortCode: "detailed-error-messages-enabled",
		Documentation: rule.RuleDocumentation{
			Summary:     "App service disables detailed error messages",
			Explanation: `Copies of the .htm error pages that would have been sent to the client browser. For security reasons, detailed error pages shouldn't be sent to clients in production, but App Service can save the error page each time an application error occurs that has HTTP code 400 or greater. The page may contain information that can help determine why the server returns the error code.`,
			Impact:      "Missing crucial details in the error messages",
			Resolution:  "Enable detailed_error_messages_enabled",
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

  logs {
    detailed_error_messages_enabled = true
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#detailed_error_messages_enabled",
				"https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"azurerm_app_service",
		},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {
			if resourceBlock.MissingChild("logs") {
				set.AddResult().
					WithDescription("Resource '%s' does not have logs enabled", resourceBlock.FullName())
				return
			}

			logProps := resourceBlock.GetBlock("logs")
			if logProps.MissingChild("detailed_error_messages_enabled") {
				set.AddResult().
					WithDescription("Resource '%s' does not have logs.detailed_error_messages_enabled block", resourceBlock.FullName()).WithBlock(logProps)
				return
			}
			detailedErrorMessagesEnabled := logProps.GetAttribute("detailed_error_messages_enabled")
			if detailedErrorMessagesEnabled.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' does not have logs.detailed_error_messages_enabled set to true", resourceBlock.FullName()).
					WithAttribute(detailedErrorMessagesEnabled)
			}
		},
	})
}
