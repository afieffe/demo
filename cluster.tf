resource "aws_ecs_cluster" "ecs_fargate" {
  name = var.cluster_name
}
