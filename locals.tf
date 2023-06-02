locals {
	aws_region = "us-east-1"
	task_def_name = "ecsngnix"
	image_name = "public.ecr.aws/z9d2n7e1/nginx"
	image_tag = "1.19.5"
	service_port = 80
}
