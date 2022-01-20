package efs

import (
	"github.com/aquasecurity/defsec/provider/aws/efs"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) efs.EFS {
	return efs.EFS{
		FileSystems: adaptFileSystems(modules),
	}
}

func adaptFileSystems(modules block.Modules) []efs.FileSystem {
	var filesystems []efs.FileSystem
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_efs_file_system") {
			filesystems = append(filesystems, adaptFileSystem(resource))
		}
	}
	return filesystems
}

func adaptFileSystem(resource block.Block) efs.FileSystem {
	encryptedAttr := resource.GetAttribute("encrypted")
	encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, resource)

	return efs.FileSystem{
		Metadata:  *resource.GetMetadata(),
		Encrypted: encryptedVal,
	}
}
