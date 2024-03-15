# dss-signing-cloud-function
Example of the Digital Signature Framework deployment as a cloud function / AWS Lambda for PDF signing  
## Build
`mvn clean package`  

## Google Cloud
### Test Locally
`mvn function:run`  
and  
`curl --data-binary "@document.pdf" -o signed.pdf localhost:8080`

### Deploy
Either manually  
`gcloud functions deploy dss-sign-pdf-http --gen2 --entry-point=com.github.alexsc.dss.SignPdfHttp --runtime=java17  --region=us-east1 --trigger-http --allow-unauthenticated --source=target/deployment`  
or using Terraform  
`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/cloudfunctions_function`
### Use
`curl --data-binary "@document.pdf" -o signed.pdf https://us-east1-alex-sc-test.cloudfunctions.net/dss-sign-pdf-http`

## AWS
### Test Locally
`mvn function:run`  
and  
`curl --data-binary "@document.pdf" -o signed.pdf localhost:8080`

### Deploy
Either manually  
`aws lambda create-function --function-name dss-sign-pdf-lambda \
--runtime java21 --handler com.github.alexsc.dss.SignPdfLambda \
--role arn:aws:iam::175379499180:role/service-role/fdfrf-role-keyh1pva \
--zip-file fileb://target/deployment/dss-signing-cloud-function-1.0.jar`  
Assign URL  
`aws lambda create-function-url-config \
 --function-name dss-sign-pdf-lambda \
 --auth-type NONE`  
or using Terraform  
`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function`

Update
`aws lambda update-function-code --function-name dss-sign-pdf-lambda  --zip-file fileb://target/deployment/dss-signing-cloud-function-1.0.jar`
### Use
`curl --data-binary "@document.pdf" -o signed.pdf https://6dagp34oy4i7f2e75viiy2kr440lifdz.lambda-url.us-east-1.on.aws/`

