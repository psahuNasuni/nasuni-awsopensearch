########################################################
##  Developed By  :   Pradeepta Kumar Sahu
##  Project       :   Nasuni ElasticSearch Integration
##  Organization  :   Nasuni Labs   
#########################################################

variable "create_iam_service_linked_role" {
  description = "Whether to create IAM service linked role for AWS ElasticSearch service. Can be only one per AWS account."
  type        = bool
  default     = false
}

variable "domain_name" {
  description = "Domain name for Elasticsearch cluster"
  type        = string
  default     = "es-domain"
}
variable "es_region" {
  description = "Region for Elasticsearch cluster"
  type        = string
  default     = "us-east-2"
}
variable "es_version" {
  description = "Version of Elasticsearch to deploy (allowed Elasticsearch Versions are: [OpenSearch_1.2, OpenSearch_1.1, OpenSearch_1.0, 7.10, 7.9, 7.8, 7.7, 7.4, 7.1, 6.8, 6.7, 6.5, 6.4, 6.3, 6.2, 6.0, 5.6, 5.5, 5.3, 5.1, 2.3, 1.5)"
  type        = string
  default     = "OpenSearch_1.2"
}

variable "instance_type" {
  description = "ES instance type for data nodes in the cluster (default t2.small.elasticsearch)"
  type        = string
  default     = "r6g.large.elasticsearch"
}

variable "instance_count" {
  description = "Number of data nodes in the cluster (default 6)"
  type        = number
  default     = 1
}

variable "dedicated_master_type" {
  description = "ES instance type to be used for dedicated masters (default same as instance_type)"
  type        = string
  default     = "false"
}

variable "encrypt_at_rest" {
  description = "Enable encrption at rest (only specific instance family types support it: m4, c4, r4, i2, i3 default: false)"
  type        = bool
  default     = false
}

variable "management_iam_roles" {
  description = "List of IAM role ARNs from which to permit management traffic (default ['*']).  Note that a client must match both the IP address and the IAM role patterns in order to be permitted access."
  type        = list(string)
  default     = ["*"]
}

variable "management_public_ip_addresses" {
  description = "List of IP addresses from which to permit management traffic (default []).  Note that a client must match both the IP address and the IAM role patterns in order to be permitted access."
  type        = list(string)
  default     = []
}

variable "es_zone_awareness" {
  description = "Enable zone awareness for Elasticsearch cluster (default false)"
  type        = bool
  default     = false
}

variable "es_zone_awareness_count" {
  description = "Number of availability zones used for data nodes (default 2)"
  type        = number
  default     = 2
}

variable "ebs_volume_size" {
  description = "Optionally use EBS volumes for data storage by specifying volume size in GB (default 0)"
  type        = number
  default     = 500
}

variable "ebs_volume_type" {
  description = "Storage type of EBS volumes, if used (default gp2)"
  type        = string
  default     = "gp2"
}

variable "kms_key_id" {
  description = "KMS key used for elasticsearch"
  type        = string
  default     = ""
}

variable "snapshot_start_hour" {
  description = "Hour at which automated snapshots are taken, in UTC (default 0)"
  type        = number
  default     = 0
}

variable "vpc_options" {
  description = "A map of supported vpc options"
  type        = map(list(string))

  default = {
    security_group_ids = []
    subnet_ids         = []
  }
}

variable "tags" {
  description = "tags to apply to all resources"
  type        = map(string)
  default = {
    Application     = "Nasuni Analytics Connector with OpenSearch"
    Developer       = "Nasuni"
    PublicationType = "Nasuni Labs"
    Version         = "V 0.1"
  }
}

variable "use_prefix" {
  description = "Flag indicating whether or not to use the domain_prefix. Default: true"
  type        = bool
  default     = true
}

variable "domain_prefix" {
  description = "String to be prefixed to search domain. Default: nasuni-labs-"
  type        = string
  default     = "nasuni-labs-"
}

variable "dedicated_master_threshold" {
  description = "The number of instances above which dedicated master nodes will be used. Default: 10"
  type        = number
  default     = 10
}

variable "advanced_options" {
  description = "Map of key-value string pairs to specify advanced configuration options. Note that the values for these configuration options must be strings (wrapped in quotes) or they may be wrong and cause a perpetual diff, causing Terraform to want to recreate your Elasticsearch domain on every apply."
  type        = map(string)
  default     = {}
}

variable "advanced_security_options_enabled" {
  type        = bool
  default     = true
  description = "AWS Elasticsearch Kibana enchanced security plugin enabling (forces new resource)"
}

variable "advanced_security_options_internal_user_database_enabled" {
  type        = bool
  default     = true
  description = "Whether to enable or not internal Kibana user database for ELK OpenDistro security plugin"
}

variable "advanced_security_options_master_user_arn" {
  type        = string
  default     = ""
  description = "ARN of IAM user who is to be mapped to be Kibana master user (applicable if advanced_security_options_internal_user_database_enabled set to false)"
}

variable "advanced_security_options_master_user_name" {
  type        = string
  default     = "nasuniadmin"
  description = "Master user username (applicable if advanced_security_options_internal_user_database_enabled set to true)"
}

variable "advanced_security_options_master_user_password" {
  type        = string
  default     = "nasuniPassword@123"
  description = "Master user password (applicable if advanced_security_options_internal_user_database_enabled set to true)"
}



variable "log_publishing_options" {
  description = "List of maps of options for publishing slow logs to CloudWatch Logs."
  type        = list(map(string))
  default     = []
}

variable "node_to_node_encryption_enabled" {
  description = "Whether to enable node-to-node encryption."
  type        = bool
  default     = false
}

variable "enforce_https" {
  description = "Whether or not to require HTTPS."
  type        = bool
  default     = false
}

variable "tls_security_policy" {
  description = "The name of the TLS security policy that needs to be applied to the HTTPS endpoint. Example values: Policy-Min-TLS-1-0-2019-07 and Policy-Min-TLS-1-2-2019-07. Terraform will only perform drift detection if a configuration value is provided."
  type        = string
  default     = "Policy-Min-TLS-1-2-2019-07"
}

variable "aws_profile" {
  type    = string
  default = "nasuni"
}

variable "admin_secret" {
  default = "nasuni-labs-os-admin"
}