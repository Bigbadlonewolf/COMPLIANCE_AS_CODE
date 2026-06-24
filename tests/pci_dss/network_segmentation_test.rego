package pci_dss.network_segmentation

import rego.v1

# GCP google_compute_firewall tests are in tests/pci_dss/req_1_test.rego.
# This file covers AWS security group rules, Azure NSRs, and pci-scope labels.

test_deny_aws_port_range_covers_non_postgres_sensitive_port if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"name": "allow_rdp_everywhere",
		"change": {"after": {
			"type": "ingress",
			"cidr_blocks": ["0.0.0.0/0"],
			"from_port": 3389,
			"to_port": 3389,
		}},
	}]}
}

test_deny_aws_wide_port_range_overlapping_sensitive_port if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"name": "allow_wide_range",
		"change": {"after": {
			"type": "ingress",
			"cidr_blocks": ["0.0.0.0/0"],
			"from_port": 1,
			"to_port": 65535,
		}},
	}]}
}

test_deny_aws_all_traffic_protocol_negative_one if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"name": "allow_all_traffic",
		"change": {"after": {
			"type": "ingress",
			"cidr_blocks": ["0.0.0.0/0"],
			"protocol": "-1",
			"from_port": 0,
			"to_port": 0,
		}},
	}]}
}

test_deny_azure_inbound_wildcard_sensitive_port if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "azurerm_network_security_rule",
		"name": "allow_mysql_from_anywhere",
		"change": {"after": {
			"direction": "Inbound",
			"access": "Allow",
			"source_address_prefix": "*",
			"destination_port_range": "3306",
		}},
	}]}
}

test_deny_azure_destination_port_range_star_wildcard if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "azurerm_network_security_rule",
		"name": "allow_everything",
		"change": {"after": {
			"direction": "Inbound",
			"access": "Allow",
			"source_address_prefix": "*",
			"destination_port_range": "*",
		}},
	}]}
}

test_deny_azure_destination_port_ranges_plural_list_form if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "azurerm_network_security_rule",
		"name": "allow_multiple_db_ports",
		"change": {"after": {
			"direction": "Inbound",
			"access": "Allow",
			"source_address_prefix": "*",
			"destination_port_ranges": ["80", "443", "3306"],
		}},
	}]}
}

test_deny_payment_service_without_pci_scope_label if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_cloud_run_v2_service",
		"name": "payment_service",
		"change": {"after": {"labels": {"team": "checkout"}}},
	}]}
}

test_deny_renamed_payment_service_still_caught if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_cloud_run_v2_service",
		"name": "checkout_orchestrator",
		"change": {"after": {"labels": {"team": "checkout"}}},
	}]}
}

test_allow_payment_service_with_pci_scope_label if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "google_cloud_run_v2_service",
		"name": "payment_service",
		"change": {"after": {"labels": {"pci-scope": "true"}}},
	}]}
}

test_allow_explicitly_out_of_scope_service if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "google_cloud_run_v2_service",
		"name": "product_catalog_service",
		"change": {"after": {"labels": {"pci-scope": "false"}}},
	}]}
}
