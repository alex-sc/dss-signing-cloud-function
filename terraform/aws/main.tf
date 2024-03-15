variable "lambda_zip" {
  default = "../../target/deployment/dss-signing-cloud-function-1.0.jar"
}

# Function itself
resource "aws_lambda_function" "test_lambda" {
  # If the file is not in the current working directory you will need to include a
  # path.module in the filename.
  filename      = var.lambda_zip
  function_name = "dss-sign-pdf-lambda-terraform"
  role          = "arn:aws:iam::175379499180:role/service-role/fdfrf-role-keyh1pva"
  handler       = "com.github.alexsc.dss.SignPdfLambda"
  runtime       = "java21"
  memory_size   = 512
  timeout       = 300
  source_code_hash = filebase64sha256(var.lambda_zip)
}

# Function URL
resource "aws_lambda_function_url" "test_lambda_url" {
  function_name      = aws_lambda_function.test_lambda.function_name
  authorization_type = "NONE"
}

# Function permissions - public
resource "aws_lambda_permission" "test_lambda_permissions" {
  statement_id  = "FunctionURLAllowPublicAccess"
  action        = "lambda:InvokeFunctionUrl"
  function_name = aws_lambda_function.test_lambda.function_name
  principal     = "*"
  function_url_auth_type = "NONE"
}
