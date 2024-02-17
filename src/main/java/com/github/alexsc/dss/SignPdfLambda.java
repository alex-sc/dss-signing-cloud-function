package com.github.alexsc.dss;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.apache.pdfbox.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SignPdfLambda implements RequestStreamHandler {

	@Override
	public void handleRequest(InputStream input, OutputStream output, Context context) throws IOException {
		byte[] inputPdfBytes = IOUtils.toByteArray(input);

		ESignEngine eSignEngine = new ESignEngine(SignatureLevel.PAdES_BASELINE_LT);
		LocalKeySigner localKeySigner = new LocalKeySigner();
		DSSDocument signedPdfBytes = eSignEngine.sign(new InMemoryDocument(inputPdfBytes), localKeySigner);

		IOUtils.copy(signedPdfBytes.openStream(), output);
	}

}
