terraform {
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

resource "local_file" "infraguard_test" {
  filename = "${path.module}/generated-test.txt"
  content  = "InfraGuard local plan test"
}
