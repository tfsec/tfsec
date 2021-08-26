package secrets

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/defsec/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/security"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

var sensitiveWhitelist = []struct {
	Resource  string
	Attribute string
}{
	{
		Resource:  "aws_efs_file_system",
		Attribute: "creation_token",
	},
	{
		Resource:  "aws_instance",
		Attribute: "get_password_data",
	},
	{
		Resource:  "github_actions_secret",
		Attribute: "secret_name",
	},
	{
		Resource:  "github_actions_organization_secret",
		Attribute: "secret_name",
	},
	{
		Resource:  "google_secret_manager_secret",
		Attribute: "secret_id",
	},
}

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GEN003",
		Base: rules.Register(rules.Rule{
			Service:    "secrets",
			ShortCode:  "sensitive-in-attribute",
			Summary:    "Potentially sensitive data stored in block attribute.",
			Impact:     "Block attribute could be leaking secrets",
			Resolution: "Don't include sensitive data in blocks",
			Explanation: `
 Sensitive attributes such as passwords and API tokens should not be available in your templates, especially in a plaintext form. You can declare variables to hold the secrets, assuming you can provide values for those variables in a secure fashion. Alternatively, you can store these secrets in a secure secret store, such as AWS KMS.
 
 *NOTE: It is also recommended to store your Terraform state in an encrypted form.*
 `,
			Links: []string{
				"https://www.terraform.io/docs/state/sensitive-data.html",
			},
			Provider: provider.GeneralProvider,
			Severity: severity.Critical,
		}, nil),
		RequiredTypes: []string{"resource", "provider", "module"},
		BadExample: []string{`
 resource "evil_corp" "bad_example" {
 	root_password = "p4ssw0rd"
 }
 `},
		GoodExample: []string{`
 variable "password" {
   description = "The root password for our VM"
   type        = string
 }
 
 resource "evil_corp" "good_example" {
 	root_password = var.passwordx
 }
 `},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			attributes := resourceBlock.GetAttributes()

		SKIP:
			for _, attribute := range attributes {
				for _, whitelisted := range sensitiveWhitelist {
					if whitelisted.Resource == resourceBlock.TypeLabel() && whitelisted.Attribute == attribute.Name() {
						continue SKIP
					}
				}
				if security.IsSensitiveAttribute(attribute.Name()) {
					if attribute.IsResolvable() && attribute.Type() == cty.String && !attribute.Equals("") {
						results.Add(
							"Attribute name appears sensitive and has a value which is defined within the project.",
							attribute.Metadata(),
							attribute.Value().AsString(),
						)
					}

				}
			}
			return
		},
	})
}
