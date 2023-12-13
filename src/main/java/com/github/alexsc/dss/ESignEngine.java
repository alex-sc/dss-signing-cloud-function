package com.github.alexsc.dss;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ESignEngine {
	private static final Logger LOG = LoggerFactory.getLogger(ESignEngine.class);

	private static final ImmutableList<String> TIMESTAMP_URLS = ImmutableList.of(
			"http://timestamp.entrust.net/TSS/RFC3161sha2TS",
			"http://timestamp.digicert.com/");

	private final CommonCertificateVerifier certificateVerifier;
	private final Set<CertificateToken> trustedCertificates = Sets.newConcurrentHashSet();

	private final PAdESService padesService;
	private final SignatureLevel signatureLevel;

	public ESignEngine(SignatureLevel signatureLevel) {
		this.signatureLevel = signatureLevel;

		// Init CommonCertificateVerifier to deal with revocation data (LTV)
		this.certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setOcspSource(new OnlineOCSPSource());
		certificateVerifier.setCrlSource(new OnlineCRLSource());

		certificateVerifier.setExtractPOEFromUntrustedChains(true);

		// To deal with existing signature/certificates if any
		certificateVerifier.setCheckRevocationForUntrustedChains(true);
		certificateVerifier.setAlertOnInvalidTimestamp(new LogOnStatusAlert());
		certificateVerifier.setAlertOnMissingRevocationData(new LogOnStatusAlert());
		certificateVerifier.setAlertOnRevokedCertificate(new LogOnStatusAlert());

		// Init PAdES service for PDF signing
		this.padesService = new PAdESService(certificateVerifier);

		// Build composite TSP source
		Map<String, TSPSource> tspSources = Maps.newLinkedHashMap();
		for (String timestampUrl : TIMESTAMP_URLS) {
			OnlineTSPSource onlineTSPSource = new OnlineTSPSource(timestampUrl);
			tspSources.put(timestampUrl, onlineTSPSource);
		}

		CompositeTSPSource compositeTSPSource = new CompositeTSPSource();
		compositeTSPSource.setTspSources(tspSources);
		padesService.setTspSource(compositeTSPSource);
	}

	public CertificateVerifier getCertificateVerifier() {
		return certificateVerifier;
	}

	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	private void addRootCertificateToTrusted(PAdESSignatureParameters parameters) {
		CertificateToken rootCertificateToken = Iterables.getLast(parameters.getCertificateChain());
		if (trustedCertificates.add(rootCertificateToken)) {
			CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
			trustedCertificateSource.addCertificate(rootCertificateToken);
			certificateVerifier.addTrustedCertSources(trustedCertificateSource);
			LOG.info("Adding signing certificate root to trusted list: {} [{}]", rootCertificateToken.getDSSIdAsString(), rootCertificateToken.getCertificate().getSubjectX500Principal().getName());
		}
	}

	public DSSDocument sign(DSSDocument pdfDocument, ExternalSigner signer) throws IOException {
		PAdESSignatureParameters parameters = new PAdESSignatureParameters();

		String signatureAlgorithmName = signer.getHashAlgorithm() + "with" + signer.getEncryptionAlgorithm();

		List<X509Certificate> certificateChain = signer.getCertificateChain();
		parameters.setSigningCertificate(new CertificateToken(certificateChain.get(0)));
		parameters.setCertificateChain(certificateChain.stream().map(CertificateToken::new).collect(Collectors.toList()));

		addRootCertificateToTrusted(parameters);

		parameters.setDigestAlgorithm(DigestAlgorithm.forName(signer.getHashAlgorithm()));
		parameters.setEncryptionAlgorithm(EncryptionAlgorithm.forName(signer.getEncryptionAlgorithm()));

		parameters.setSignatureLevel(signatureLevel);

		// Compute PDF digest
		ToBeSigned dataToSign = padesService.getDataToSign(pdfDocument, parameters);

		// Sign the digest
		byte[] signedData;
		try {
			signedData = signer.sign(dataToSign.getBytes());
		} catch (SignatureException e) {
			LOG.error("Error signing PDF digest", e);
			throw new IOException(e);
		}
		SignatureValue signatureValue = new SignatureValue(SignatureAlgorithm.forJAVA(signatureAlgorithmName), signedData);

		// Embed the signature into PDF
		return padesService.signDocument(pdfDocument, parameters, signatureValue);
	}
}
