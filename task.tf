resource "aws_ecs_task_definition" "nginx" {
  family                   = local.task_def_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  execution_role_arn       = "arn:aws:iam::807828924102:role/ecsTaskExecutionRole"
  memory                   = "2048"
  cpu                      = "1024"
  container_definitions = templatefile("template.json.tpl", {
    app_name      = "nginx",
    repository_url = local.image_name
  })
}
