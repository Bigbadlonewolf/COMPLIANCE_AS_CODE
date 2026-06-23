package pci_dss.network_segmentation

import future.keywords.if

test_deny_open_ssh_ingress if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_compute_firewall",
		"name": "allow_ssh_everywhere",
		"change": {"after": {
			"source_ranges": ["0.0.0.0/0"],
			"allow": [{"ports": ["22"]}],
		}},
	}]}
}

test_allow_restricted_ssh_ingress if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "google_compute_firewall",
		"name": "allow_ssh_internal_only",
		"change": {"after": {
			"source_ranges": ["10.0.0.0/8"],
			"allow": [{"ports": ["22"]}],
		}},
	}]}
}

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

test_deny_aws_all_traffic_protocol_negative_one if {
	# Regression test: AWS expresses "all traffic, all ports" as
	# protocol = "-1", commonly with from_port/to_port = 0. Generalizing
	# that to a "0-0" range check catches nothing, because 0 isn't in the
	# sensitive_ports set — this needs a direct protocol check.
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

test_deny_payment_service_without_pci_scope_label if {
	count(deny) > 0 with input as {"resource_changes": [{
		"type": "google_cloud_run_v2_service",
		"name": "payment_service",
		"change": {"after": {"labels": {"team": "checkout"}}},
	}]}
}

test_deny_renamed_payment_service_still_caught if {
	# This is the regression test for the name-based bypass a reviewer
	# found: a service doing the exact same job as "payment_service" but
	# named something innocuous must still be caught, because the rule no
	# longer keys off the name at all.
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
