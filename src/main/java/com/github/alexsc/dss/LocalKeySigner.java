package com.github.alexsc.dss;

import com.github.alexsc.util.ESignTestUtils;
import com.google.common.collect.Lists;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

public class LocalKeySigner implements ExternalSigner {

	@Override
	public List<X509Certificate> getCertificateChain() {
		return Lists.newArrayList(ESignTestUtils.getTestCertificateChain());
	}

	@Override
	public byte[] sign(byte[] message) throws IOException {
		try {
			return ESignTestUtils.sign(message);
		} catch (Exception e) {
			throw new IOException(e);
		}
	}

}
