package cloudfront

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSCloudFrontOutdatedProtocol(t *testing.T) {
	expectedCode := "aws-cloudfront-use-secure-tls-policy"
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check no viewer_certificate block in aws_cloudfront_distribution",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {

}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check no default minimum_protocol_version attribute in viewer_certificate block",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
  viewer_certificate {
    cloudfront_default_certificate = false
  }
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check TLSv1.2_2019 not used",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
  viewer_certificate {
    cloudfront_default_certificate = false
	minimum_protocol_version = "TLSv1.2_2018"
  }
}`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "check don't trigger if cloudfront_default_certificate is set to true",
			source: `
resource "aws_cloudfront_distribution" "s3_distribution" {
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
