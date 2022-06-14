########################################################
##  Developed By  :   Pradeepta Kumar Sahu
##  Project       :   Nasuni ElasticSearch Integration
##  Organization  :   Nasuni Labs   
#########################################################

locals {
  domain_name = var.use_prefix ? join("", [lower(var.domain_prefix), lower(var.domain_name), "-", lower(random_id.es_unique_id.hex)]) : lower(var.domain_name)
  inside_vpc  = length(var.vpc_options["subnet_ids"]) > 0 ? true : false
}
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "es_management_access" {
  count = false == local.inside_vpc ? 1 : 0

  statement {
    actions = [
      "es:*",
    ]

    resources = [
      aws_elasticsearch_domain.es[0].arn,
      "${aws_elasticsearch_domain.es[0].arn}/*",
    ]

    principals {
      type = "AWS"
      /* identifiers = ["*"] */
      identifiers = distinct(compact(var.management_iam_roles))
    }

    /* condition {
      test     = "IpAddress"
      variable = "aws:SourceIp"

      values = distinct(compact(var.management_public_ip_addresses))
    } */
  }
}

resource "random_id" "es_unique_id" {
  byte_length = 3
}

data "aws_security_groups" "es" {
  filter {
    name   = "vpc-id"
    values = [var.user_vpc_id]
  }
}

resource "aws_elasticsearch_domain" "es" {
  count = false == local.inside_vpc ? 1 : 0

  depends_on = [aws_iam_service_linked_role.es]

  domain_name           = lower(local.domain_name)
  elasticsearch_version = var.es_version

  encrypt_at_rest {
    /* enabled    = var.encrypt_at_rest */
    enabled    = true
    kms_key_id = var.kms_key_id
  }

  domain_endpoint_options {
    enforce_https = true
    /* enforce_https       = var.enforce_https */
    tls_security_policy = var.tls_security_policy
  }

  cluster_config {
    instance_type            = var.instance_type
    instance_count           = var.instance_count
    dedicated_master_enabled = var.instance_count >= var.dedicated_master_threshold ? true : false
    dedicated_master_count   = var.instance_count >= var.dedicated_master_threshold ? 3 : 0
    dedicated_master_type    = var.instance_count >= var.dedicated_master_threshold ? var.dedicated_master_type != "false" ? var.dedicated_master_type : var.instance_type : ""
    zone_awareness_enabled   = var.es_zone_awareness
    dynamic "zone_awareness_config" {
      for_each = var.es_zone_awareness ? [var.es_zone_awareness_count] : []
      content {
        availability_zone_count = zone_awareness_config.value
      }
    }
  }

  advanced_options = var.advanced_options

  advanced_security_options {
    enabled                        = var.advanced_security_options_enabled
    internal_user_database_enabled = var.advanced_security_options_internal_user_database_enabled
    master_user_options {
      /* master_user_arn      = var.advanced_security_options_master_user_arn       */
      master_user_name     = var.advanced_security_options_master_user_name
      master_user_password = var.advanced_security_options_master_user_password
    }
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es-log-group.arn
    enabled                  = true
    log_type                 = var.es_log_type
  }


  node_to_node_encryption {
    /* enabled = var.node_to_node_encryption_enabled */
    enabled = true
  }

  ebs_options {
    ebs_enabled = var.ebs_volume_size > 0 ? true : false
    volume_size = var.ebs_volume_size
    volume_type = var.ebs_volume_type
  }

  snapshot_options {
    automated_snapshot_start_hour = var.snapshot_start_hour
  }

  vpc_options {
    subnet_ids = [var.user_subnet_id]
    security_group_ids = [data.aws_security_groups.es.ids[0]]
  }

  tags = merge(
    {
      "Domain" = lower(local.domain_name)
    },
    var.tags,
  )
}

resource "aws_elasticsearch_domain_policy" "es_management_access" {
  count = false == local.inside_vpc ? 1 : 0

  domain_name     = lower(local.domain_name)
  access_policies = data.aws_iam_policy_document.es_management_access[0].json

}
##########################################
resource "aws_cloudwatch_log_group" "es-log-group" {
  name = "es-log-group"
}

resource "aws_cloudwatch_log_resource_policy" "es-log-policy" {
  policy_name = "nasuni-es-log-policy"

  policy_document = <<CONFIG
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Action": [
        "logs:PutLogEvents",
        "logs:PutLogEventsBatch",
        "logs:CreateLogStream"
      ],
      "Resource": "arn:aws:logs:*"
    }
  ]
}
CONFIG
}

#########################################


################# Update Admin Secret with ES Data ######################

### "Nasuni Analytics Connector's Admin specific internal secret. This will be created By admins Manually and Updated by  Terraform Code after the Elasticsearch domain Provisioning completed."

data "aws_secretsmanager_secret" "admin_secret" {
  name = var.admin_secret
}
resource "aws_secretsmanager_secret_version" "admin_secret" {
  secret_id     = data.aws_secretsmanager_secret.admin_secret.id
  secret_string = jsonencode(local.admin_secret_data_to_update)
  depends_on = [
    aws_elasticsearch_domain.es,
    data.aws_secretsmanager_secret.admin_secret,
  ]
} 


locals {
  admin_secret_data_to_update = {
    nac_es_url = element(
                  concat(
                    aws_elasticsearch_domain.es_vpc.*.endpoint,
                    aws_elasticsearch_domain.es.*.endpoint,
                    [""],
                  ),
                  0,
                )
    nac_kibana_url = element(
                      concat(
                          aws_elasticsearch_domain.es_vpc.*.kibana_endpoint,
                          aws_elasticsearch_domain.es.*.kibana_endpoint,
                          [""],
                        ),
                        0,
                      )
    es_domain_name = element(
                      concat(
                        aws_elasticsearch_domain.es_vpc.*.domain_name,
                        aws_elasticsearch_domain.es.*.domain_name,
                        [""],
                      ),
                      0,
                    )
    nac_es_admin_user = var.advanced_security_options_master_user_name 
    nac_es_admin_password = var.advanced_security_options_master_user_password
    es_region = var.es_region
    /* es_domain_status =  */

  }
}
