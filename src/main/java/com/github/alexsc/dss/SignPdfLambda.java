package com.github.alexsc.dss;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.apache.pdfbox.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Base64;

public class SignPdfLambda implements RequestStreamHandler {

	@Override
	public void handleRequest(InputStream input, OutputStream output, Context context) throws IOException {
		byte[] inputPdfBytes = IOUtils.toByteArray(input);
		try {
			String base64Pdf = new ObjectMapper().readTree(inputPdfBytes).get("body").asText();
			byte[] pdfBytes = Base64.getDecoder().decode(base64Pdf);

			ESignEngine eSignEngine = new ESignEngine(SignatureLevel.PAdES_BASELINE_LT);
			LocalKeySigner localKeySigner = new LocalKeySigner();
			DSSDocument signedPdfBytes = eSignEngine.sign(new InMemoryDocument(pdfBytes), localKeySigner);
	
			IOUtils.copy(signedPdfBytes.openStream(), output);
		} catch (Throwable e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			String sStackTrace = sw.toString();
			sStackTrace = new String(inputPdfBytes).substring(0, 10) + "\n" + sStackTrace;
			output.write(sStackTrace.getBytes());
		} finally {
			input.close();
			output.close();
		}
	}

}
