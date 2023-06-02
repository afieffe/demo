terraform {
  required_providers {
    lacework = {
      source = "lacework/lacework"
      version = "1.4.0"
    }
  }
}

provider aws {
    region = "eu-west-1"
}

provider "lacework" {
  alias = "arnaud"
}




