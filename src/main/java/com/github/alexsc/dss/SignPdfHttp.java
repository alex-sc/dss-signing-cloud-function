package com.github.alexsc.dss;

import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.apache.pdfbox.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;

public class SignPdfHttp implements HttpFunction {
	@Override
	public void service(HttpRequest request, HttpResponse response) throws IOException {
		byte[] inputPdfBytes;
		try (InputStream inputStream = request.getInputStream()) {
			inputPdfBytes = IOUtils.toByteArray(request.getInputStream());
		}

		ESignEngine eSignEngine = new ESignEngine(SignatureLevel.PAdES_BASELINE_LT);
		LocalKeySigner localKeySigner = new LocalKeySigner();
		DSSDocument signedPdfBytes = eSignEngine.sign(new InMemoryDocument(inputPdfBytes), localKeySigner);

		IOUtils.copy(signedPdfBytes.openStream(), response.getOutputStream());
	}
}
