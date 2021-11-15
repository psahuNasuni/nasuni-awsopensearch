Terraform Scripts to provision ElasticSearch in AWS for Nasuni_ElasticSearch Integration Project.

Description
Using Terraform, Provision ES Cluster for Nasuni in AWS.

terraform init

terraform validate

terraform fmt

terraform plan -var-file=dev.tfvars 

terraform apply -var-file=dev.tfvars -auto-approve

terraform destroy -var-file=dev.tfvars -auto-approve
