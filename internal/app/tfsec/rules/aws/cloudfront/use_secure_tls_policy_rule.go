package cloudfront

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS021",
		Service:   "cloudfront",
		ShortCode: "use-secure-tls-policy",
		Documentation: rule.RuleDocumentation{
			Summary:    "CloudFront distribution uses outdated SSL/TLS protocols.",
			Impact:     "Outdated SSL policies increase exposure to known vulnerabilities",
			Resolution: "Use the most modern TLS/SSL policies available",
			Explanation: `
You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
`,
			BadExample: []string{`
resource "aws_cloudfront_distribution" "bad_example" {
  viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version = "TLSv1.0"
  }
}
`},
			GoodExample: []string{`
resource "aws_cloudfront_distribution" "good_example" {
  viewer_certificate {
    cloudfront_default_certificate = false
    minimum_protocol_version = "TLSv1.2_2021"
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#minimum_protocol_version",
				"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_cloudfront_distribution"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, context block.Module) {

			viewerCertificateBlock := resourceBlock.GetBlock("viewer_certificate")
			if viewerCertificateBlock.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines outdated SSL/TLS policies (missing viewer_certificate block)", resourceBlock.FullName())
				return
			}

			defaultCertificateAttr := viewerCertificateBlock.GetAttribute("cloudfront_default_certificate")
			if defaultCertificateAttr.IsTrue() {
				return
			}

			minVersionAttr := viewerCertificateBlock.GetAttribute("minimum_protocol_version")
			if minVersionAttr.IsNil() {
				set.AddResult().
					WithDescription("Resource '%s' defines outdated SSL/TLS policies (missing minimum_protocol_version attribute)", resourceBlock.FullName()).
					WithBlock(viewerCertificateBlock)
				return
			}

			if minVersionAttr.NotEqual("TLSv1.2_2021") {
				set.AddResult().
					WithDescription("Resource '%s' defines outdated SSL/TLS policies (not using TLSv1.2_2021)", resourceBlock.FullName()).
					WithAttribute(minVersionAttr)
			}
		},
	})
}
