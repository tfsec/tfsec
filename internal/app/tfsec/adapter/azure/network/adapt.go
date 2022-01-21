package network

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/defsec/provider/azure/network"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/google/uuid"
)

func Adapt(modules block.Modules) network.Network {
	return network.Network{
		SecurityGroups: (&adapter{
			modules: modules,
			groups:  make(map[string]network.SecurityGroup),
		}).adaptSecurityGroups(),
		NetworkWatcherFlowLogs: adaptWatcherLogs(modules),
	}
}

type adapter struct {
	modules block.Modules
	groups  map[string]network.SecurityGroup
}

func (a *adapter) adaptSecurityGroups() []network.SecurityGroup {

	for _, module := range a.modules {
		for _, resource := range module.GetResourcesByType("azurerm_network_security_group") {
			a.adaptSecurityGroup(resource)
		}
	}

	for _, ruleBlock := range a.modules.GetResourcesByType("azurerm_network_security_rule") {
		rule := a.adaptSGRule(ruleBlock)

		groupAttr := ruleBlock.GetAttribute("network_security_group_name")
		if groupAttr.IsNotNil() {
			if referencedBlock, err := a.modules.GetReferencedBlock(groupAttr, ruleBlock); err == nil {
				if group, ok := a.groups[referencedBlock.ID()]; ok {
					group.Rules = append(group.Rules, rule)
					a.groups[referencedBlock.ID()] = group
					continue
				}
			}

		}

		a.groups[uuid.NewString()] = network.SecurityGroup{
			Rules: []network.SecurityGroupRule{rule},
		}
	}

	var securityGroups []network.SecurityGroup
	for _, group := range a.groups {
		securityGroups = append(securityGroups, group)
	}

	return securityGroups
}

func adaptWatcherLogs(modules block.Modules) []network.NetworkWatcherFlowLog {
	var watcherLogs []network.NetworkWatcherFlowLog

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_network_watcher_flow_log") {
			watcherLogs = append(watcherLogs, adaptWatcherLog(resource))
		}
	}
	return watcherLogs
}

func (a *adapter) adaptSecurityGroup(resource block.Block) {
	var rules []network.SecurityGroupRule
	for _, ruleBlock := range resource.GetBlocks("security_rule") {
		rules = append(rules, a.adaptSGRule(ruleBlock))
	}
	a.groups[resource.ID()] = network.SecurityGroup{
		Rules: rules,
	}
}

func (a *adapter) adaptSGRule(ruleBlock block.Block) network.SecurityGroupRule {

	rule := network.SecurityGroupRule{
		Metadata: ruleBlock.Metadata(),
		Allow:    types.BoolDefault(true, ruleBlock.Metadata()),
		Outbound: types.BoolDefault(false, ruleBlock.Metadata()),
	}

	accessAttr := ruleBlock.GetAttribute("access")
	if accessAttr.Equals("Allow") {
		rule.Allow = types.Bool(true, accessAttr.Metadata())
	} else if accessAttr.Equals("Deny") {
		rule.Allow = types.Bool(false, accessAttr.Metadata())
	}

	directionAttr := ruleBlock.GetAttribute("direction")
	if directionAttr.Equals("Inbound") {
		rule.Outbound = types.Bool(false, directionAttr.Metadata())
	} else if directionAttr.Equals("Outbound") {
		rule.Outbound = types.Bool(true, directionAttr.Metadata())
	}

	if sourceAddressAttr := ruleBlock.GetAttribute("source_address_prefix"); sourceAddressAttr.IsString() {
		rule.SourceAddresses = append(rule.SourceAddresses, sourceAddressAttr.AsStringValueOrDefault("", ruleBlock))
	} else if sourceAddressPrefixesAttr := ruleBlock.GetAttribute("source_address_prefixes"); sourceAddressPrefixesAttr.IsNotNil() {
		for _, prefix := range sourceAddressPrefixesAttr.ValueAsStrings() {
			rule.SourceAddresses = append(rule.SourceAddresses, types.String(prefix, sourceAddressPrefixesAttr.Metadata()))
		}
	}

	if sourcePortRangesAttr := ruleBlock.GetAttribute("source_port_ranges"); sourcePortRangesAttr.IsNotNil() {
		for _, value := range sourcePortRangesAttr.ValueAsStrings() {
			rule.SourcePorts = append(rule.SourcePorts, expandRange(value, sourcePortRangesAttr.Metadata())...)
		}
	} else if sourcePortRangeAttr := ruleBlock.GetAttribute("source_port_range"); sourcePortRangeAttr.IsString() {
		rule.SourcePorts = append(rule.SourcePorts, expandRange(sourcePortRangeAttr.Value().AsString(), sourcePortRangeAttr.Metadata())...)
	} else if sourcePortRangeAttr := ruleBlock.GetAttribute("source_port_range"); sourcePortRangeAttr.IsNumber() {
		bf := sourcePortRangeAttr.Value().AsBigFloat()
		f, _ := bf.Float64()
		rule.SourcePorts = append(rule.SourcePorts, types.Int(int(f), sourcePortRangeAttr.Metadata()))
	}

	if destAddressAttr := ruleBlock.GetAttribute("destination_address_prefix"); destAddressAttr.IsString() {
		rule.DestinationAddresses = append(rule.DestinationAddresses, destAddressAttr.AsStringValueOrDefault("", ruleBlock))
	} else if destAddressPrefixesAttr := ruleBlock.GetAttribute("destination_address_prefixes"); destAddressPrefixesAttr.IsNotNil() {
		for _, prefix := range destAddressPrefixesAttr.ValueAsStrings() {
			rule.DestinationAddresses = append(rule.DestinationAddresses, types.String(prefix, destAddressPrefixesAttr.Metadata()))
		}
	}

	if destPortRangesAttr := ruleBlock.GetAttribute("destination_port_ranges"); destPortRangesAttr.IsNotNil() {
		for _, value := range destPortRangesAttr.ValueAsStrings() {
			rule.DestinationPorts = append(rule.DestinationPorts, expandRange(value, destPortRangesAttr.Metadata())...)
		}
	} else if destPortRangeAttr := ruleBlock.GetAttribute("destination_port_range"); destPortRangeAttr.IsString() {
		rule.DestinationPorts = append(rule.DestinationPorts, expandRange(destPortRangeAttr.Value().AsString(), destPortRangeAttr.Metadata())...)
	} else if destPortRangeAttr := ruleBlock.GetAttribute("destination_port_range"); destPortRangeAttr.IsNumber() {
		bf := destPortRangeAttr.Value().AsBigFloat()
		f, _ := bf.Float64()
		rule.DestinationPorts = append(rule.DestinationPorts, types.Int(int(f), destPortRangeAttr.Metadata()))
	}

	return rule
}

func expandRange(r string, m types.Metadata) []types.IntValue {
	start := 0
	end := 65535
	switch {
	case r == "*":
	case strings.Contains(r, "-"):
		if parts := strings.Split(r, "-"); len(parts) == 2 {
			if p1, err := strconv.ParseInt(parts[0], 10, 32); err == nil {
				start = int(p1)
			}
			if p2, err := strconv.ParseInt(parts[1], 10, 32); err == nil {
				end = int(p2)
			}
		}
	default:
		if val, err := strconv.ParseInt(r, 10, 32); err == nil {
			start = int(val)
			end = int(val)
		}
	}
	var ports []types.IntValue
	for i := start; i <= end; i++ {
		ports = append(ports, types.Int(i, m))
	}
	return ports
}

func adaptWatcherLog(resource block.Block) network.NetworkWatcherFlowLog {
	retentionPolicyBlock := resource.GetBlock("retention_policy")

	enabledAttr := retentionPolicyBlock.GetAttribute("enabled")
	enabledVal := enabledAttr.AsBoolValueOrDefault(false, retentionPolicyBlock)

	daysAttr := retentionPolicyBlock.GetAttribute("days")
	daysVal := daysAttr.AsIntValueOrDefault(0, retentionPolicyBlock)

	return network.NetworkWatcherFlowLog{
		RetentionPolicy: network.RetentionPolicy{
			Enabled: enabledVal,
			Days:    daysVal,
		},
	}
}
