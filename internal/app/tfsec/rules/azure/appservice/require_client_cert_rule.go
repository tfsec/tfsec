package appservice
// 
// // ATTENTION!
// // This rule was autogenerated!
// // Before making changes, consider updating the generator.
// 
// import (
// 	"github.com/aquasecurity/defsec/provider"
// 	"github.com/aquasecurity/defsec/result"
// 	"github.com/aquasecurity/defsec/severity"
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
// 	"github.com/aquasecurity/tfsec/pkg/rule"
// )
// 
// func init() {
// 	scanner.RegisterCheckRule(rule.Rule{
// 		Provider:  provider.AzureProvider,
// 		Service:   "appservice",
// 		ShortCode: "require-client-cert",
// 		Documentation: rule.RuleDocumentation{
// 			Summary:     "Web App accepts incoming client certificate",
// 			Explanation: `The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled only an authenticated client with valid certificates can access the app.`,
// 			Impact:      "Mutual TLS is not being used",
// 			Resolution:  "Enable incoming certificates for clients",
// 			BadExample: []string{`
// resource "azurerm_app_service" "bad_example" {
//   name                = "example-app-service"
//   location            = azurerm_resource_group.example.location
//   resource_group_name = azurerm_resource_group.example.name
//   app_service_plan_id = azurerm_app_service_plan.example.id
// }
// `,
// 				`
// resource "azurerm_app_service" "bad_example" {
//   name                = "example-app-service"
//   location            = azurerm_resource_group.example.location
//   resource_group_name = azurerm_resource_group.example.name
//   app_service_plan_id = azurerm_app_service_plan.example.id
//   client_cert_enabled = false
// }
// `,
// 			},
// 			GoodExample: []string{`
// resource "azurerm_app_service" "good_example" {
//   name                = "example-app-service"
//   location            = azurerm_resource_group.example.location
//   resource_group_name = azurerm_resource_group.example.name
//   app_service_plan_id = azurerm_app_service_plan.example.id
//   client_cert_enabled = true
// }
// `},
// 			Links: []string{
// 				"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#client_cert_enabled",
// 			},
// 		},
// 		RequiredTypes: []string{
// 			"resource",
// 		},
// 		RequiredLabels: []string{
// 			"azurerm_app_service",
// 		},
// 		DefaultSeverity: severity.Low,
// 		CheckTerraform: func(set result.Set, resourceBlock block.Block, module block.Module) {
// 			if clientCertEnabledAttr := resourceBlock.GetAttribute("client_cert_enabled"); clientCertEnabledAttr.IsNil() { // alert on use of default value
// 				set.AddResult().
// 					WithDescription("Resource '%s' uses default value for client_cert_enabled", resourceBlock.FullName())
// 			} else if clientCertEnabledAttr.IsFalse() {
// 				set.AddResult().
// 					WithDescription("Resource '%s' has attribute client_cert_enabled that is false", resourceBlock.FullName()).
// 					WithAttribute("")
// 			}
// 		},
// 	})
// }