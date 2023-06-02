resource "aws_ecs_service" "main" {
 name                               = "${local.task_def_name}-service-test"
 cluster                            = aws_ecs_cluster.ecs_fargate.id
 task_definition                    = aws_ecs_task_definition.nginx.arn
 desired_count                      = 2
 deployment_minimum_healthy_percent = 50
 deployment_maximum_percent         = 200
 launch_type                        = "FARGATE"
 scheduling_strategy                = "REPLICA"

 network_configuration {
   security_groups  = ["sg-00d1eac640475517d"]
   subnets          = [ "subnet-0eda8d9af36974ad8"]
   assign_public_ip = true
 }

 lifecycle {
   ignore_changes = [task_definition, desired_count]
 }
}