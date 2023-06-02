# Create AWS SSM Document
module "lacework_aws_ssm_agents_install" {
  source = "lacework/ssm-agent/aws"
  version = "~> 0.8"

  lacework_agent_tags = {
    env = "testing-smm"
  }

  aws_resources_tags = {
    billing = "testing"
    owner   = "arnaud"
  }
  aws_resources_prefix = "arnaud"
  lacework_access_token = "a3504507eeafc25174b0cff8edd143ffb3821f76e9de1603b3dc5f75"
  lacework_server_url = "https://api.fra.lacework.net"
}

resource "aws_resourcegroups_group" "testing" {
  name = "arnaud-testing"

  resource_query {
    query = jsonencode({
      ResourceTypeFilters = [
        "AWS::EC2::Instance"
      ]

      TagFilters = [
        {
          Key = "environment"
          Values = [
            "arnaud-testing"
          ]
        }
      ]
    })
  }
    tags = {
    billing = "testing"
    owner   = "myself"
  }
}


resource "aws_ssm_association" "lacework_aws_ssm_agents_install_testing" {
  association_name = "install-lacework-agents-arnaud-testing-group"

  name = module.lacework_aws_ssm_agents_install.ssm_document_name

  targets {
    key = "resource-groups:Name"
    values = [
      aws_resourcegroups_group.testing.name,
    ]
  }

  compliance_severity = "HIGH"
}


