# dss-signing-cloud-function
Example of the Digital Signature Framework deployment as a cloud function for PDF signing  
## Build
`mvn clean package`  

## Test Locally
`mvn function:run`  
and  
`curl --data-binary "@document.pdf" -o signed.pdf localhost:8080`

## Deploy
Either manually  
`gcloud functions deploy dss-sign-pdf-http --gen2 --entry-point=com.github.alexsc.dss.SignPdfHttp --runtime=java17  --region=us-east1 --trigger-http --allow-unauthenticated --source=target/deployment`
or using Terraform  
https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/cloudfunctions_function
`...`
## Test
`curl --data-binary "@document.pdf" -o signed.pdf https://us-east1-alex-sc-test.cloudfunctions.net/dss-sign-pdf-http`