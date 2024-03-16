package com.github.alexsc.dss;

import com.microsoft.azure.functions.*;
import com.microsoft.azure.functions.annotation.*;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.io.IOException;
import java.util.Base64;
import java.util.Optional;

public class SignPdfAzure {
	@FunctionName("dss-sign-pdf-function-port")
	@StorageAccount("AzureWebJobsStorage")
	public byte[] run(
			@HttpTrigger(
					name = "req",
					methods = HttpMethod.POST,
//					dataType = "binary",
					authLevel = AuthorizationLevel.ANONYMOUS)
			HttpRequestMessage<Optional<String>> request,
			final ExecutionContext context) throws IOException {
		byte[] inputPdfBytes = Base64.getDecoder().decode(request.getBody().get());
		ESignEngine eSignEngine = new ESignEngine(SignatureLevel.PAdES_BASELINE_LT);
		LocalKeySigner localKeySigner = new LocalKeySigner();
		DSSDocument signedPdfBytes = eSignEngine.sign(new InMemoryDocument(inputPdfBytes), localKeySigner);
		return signedPdfBytes.openStream().readAllBytes();
	}
}
