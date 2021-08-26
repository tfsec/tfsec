package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

var panicRule = rule.Rule{
	LegacyID:  "EXA001",
	Provider:  provider.AWSProvider,
	Service:   "service",
	ShortCode: "abc",
	Documentation: rule.RuleDocumentation{
		Summary:     "A stupid example check for a test.",
		Impact:      "You will look stupid",
		Resolution:  "Don't do stupid stuff",
		Explanation: "Panic should not be set.",
		BadExample: []string{`
resource "problem" "x" {
panic = true
}
`},
		GoodExample: []string{`
resource "problem" "x" {

}
`},
		Links: nil,
	},
	RequiredTypes:   []string{"resource"},
	RequiredLabels:  []string{"problem"},
	DefaultSeverity: severity.High,
	CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
		if resourceBlock.GetAttribute("panic").IsTrue() {
			panic("This is fine")
		}
	},
}

func Test_PanicInCheckNotAllowed(t *testing.T) {

	scanner.RegisterCheckRule(panicRule)
	defer scanner.DeregisterCheckRule(panicRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
resource "problem" "this" {
	panic = true
}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New(scanner.OptionIgnoreCheckErrors(true)).Scan(blocks)
	testutil.AssertCheckCode(t, "", panicRule.ID(), results)
}

func Test_PanicInCheckAllowed(t *testing.T) {

	scanner.RegisterCheckRule(panicRule)
	defer scanner.DeregisterCheckRule(panicRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
resource "problem" "this" {
	panic = true
}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	scan := scanner.New(scanner.OptionIgnoreCheckErrors(false))
	assert.Panics(t, func() {
		scan.Scan(blocks)
	})
}

func Test_PanicInCheckIncludePassed(t *testing.T) {

	scanner.RegisterCheckRule(panicRule)
	defer scanner.DeregisterCheckRule(panicRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
resource "problem" "this" {
	panic = true
}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New(scanner.OptionIgnoreCheckErrors(true), scanner.OptionIncludePassed()).Scan(blocks)
	testutil.AssertCheckCode(t, "", panicRule.ID(), results)
}
