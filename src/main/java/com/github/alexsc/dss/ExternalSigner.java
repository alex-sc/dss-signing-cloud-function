package com.github.alexsc.dss;

import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;

public interface ExternalSigner {
	List<X509Certificate> getCertificateChain();

	byte[] sign(byte[] message) throws SignatureException, IOException;

	default X509Certificate getSigningCertificate() {
		return getCertificateChain().get(0);
	}

	default String getHashAlgorithm() {
		String signAlgName = getSigningCertificate().getSigAlgName();
		return signAlgName.substring(0, signAlgName.toLowerCase().lastIndexOf("with"));
	}

	default String getEncryptionAlgorithm() {
		return getSigningCertificate().getPublicKey().getAlgorithm();
	}
}
