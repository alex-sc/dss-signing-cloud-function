package com.github.alexsc.util;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import static com.github.alexsc.util.CertificateGenerator.*;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.Objects;

public class ESignTestUtils {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static RSAPrivateKey CA_KEY;
	private static X509Certificate CA_CERTIFICATE;
	static {
		try {
			KeyStore sslKeyStore = KeyStore.getInstance(KEYSTORE_TYPE, BC_PROVIDER);
			sslKeyStore.load(ESignTestUtils.class.getResourceAsStream("/root-cert.pfx"), CA_CERT_PASSWORD.toCharArray());
			CA_KEY = (RSAPrivateKey) sslKeyStore.getKey(CA_CERT_ALIAS, null);
			CA_CERTIFICATE = (X509Certificate) sslKeyStore.getCertificate(CA_CERT_ALIAS);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static RSAPrivateKey USER_KEY;
	private static X509Certificate USER_CERTIFICATE;
	static {
		try {
			KeyStore sslKeyStore = KeyStore.getInstance(KEYSTORE_TYPE, BC_PROVIDER);
			sslKeyStore.load(ESignTestUtils.class.getResourceAsStream("/issued-cert.pfx"), USER_CERT_PASSWORD.toCharArray());
			USER_KEY = (RSAPrivateKey) sslKeyStore.getKey(USER_CERT_ALIAS, null);
			USER_CERTIFICATE = (X509Certificate) sslKeyStore.getCertificate(USER_CERT_ALIAS);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static final AlgorithmIdentifier SIGNATURE_ID = Objects.requireNonNull(new DefaultSignatureAlgorithmIdentifierFinder().find(SIGNATURE_ALGORITHM));
	private static final AlgorithmIdentifier DIGEST_ID = Objects.requireNonNull(new DefaultDigestAlgorithmIdentifierFinder().find(DIGEST_ALGORITHM));
	private static final AlgorithmIdentifier OCSP_DIGEST_ID = Objects.requireNonNull(new DefaultDigestAlgorithmIdentifierFinder().find("SHA1"));

	public static RSAPrivateKey getTestPrivateKey() {
		return USER_KEY;
	}

	public static byte[] sign(byte[] message) throws Exception {
		Signature sig = Signature.getInstance(USER_CERTIFICATE.getSigAlgName());
		sig.initSign(USER_KEY);
		sig.update(message);
		return sig.sign();
	}

	// https://stackoverflow.com/questions/43490188/separate-digest-signing-using-java-security-provider
	public static byte[] signWithoutHashing(byte[] digest) throws Exception {
		byte[] wrappedDigest = wrapForRsaSign(digest, DIGEST_ALGORITHM);

		Signature sig = Signature.getInstance("NONEwith" + KEY_ALGORITHM);
		sig.initSign(USER_KEY);
		sig.update(wrappedDigest);
		return sig.sign();
	}

	private static byte[] wrapForRsaSign(byte[] digest, String hashAlgo) throws IOException {
		ASN1ObjectIdentifier oid = new DefaultDigestAlgorithmIdentifierFinder().find(hashAlgo).getAlgorithm();
		ASN1Sequence oidSeq = new DERSequence(new ASN1Encodable[] { oid, DERNull.INSTANCE });
		ASN1Sequence seq = new DERSequence(new ASN1Encodable[] { oidSeq, new DEROctetString(digest) });
		return seq.getEncoded();
	}

	public static X509Certificate[] getTestCertificateChain() {
		return new X509Certificate[] {USER_CERTIFICATE, CA_CERTIFICATE};
	}

	public static byte[] generateOcsp() throws Exception {
		SubjectPublicKeyInfo issuedCertificateKeyInfo = new SubjectPublicKeyInfo(SIGNATURE_ID, USER_CERTIFICATE.getPublicKey().getEncoded());
		DigestCalculator digestCalculator = new BcDigestCalculatorProvider().get(OCSP_DIGEST_ID);

		X509CertificateHolder rootCertificateHolder = new X509CertificateHolder(CA_CERTIFICATE.getEncoded());
		CertificateID certificateID = new CertificateID(digestCalculator, rootCertificateHolder, USER_CERTIFICATE.getSerialNumber());

		BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(issuedCertificateKeyInfo, digestCalculator);
		builder.addResponse(certificateID, CertificateStatus.GOOD);

		RSAKeyParameters keyParameters = new RSAKeyParameters(true, CA_KEY.getModulus(), CA_KEY.getPrivateExponent());
		ContentSigner signer = new BcRSAContentSignerBuilder(SIGNATURE_ID, DIGEST_ID).build(keyParameters);
		X509CertificateHolder[] chain = new X509CertificateHolder[] {rootCertificateHolder};
		BasicOCSPResp basicOCSPResp = builder.build(signer, chain, new Date());

		OCSPRespBuilder ocspRespBuilder = new OCSPRespBuilder();
		OCSPResp ocspResp = ocspRespBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicOCSPResp);

		return ocspResp.getEncoded();
	}

	private static Date calculateDate(int hoursInFuture) {
		long secs = System.currentTimeMillis() / 1000;

		return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
	}

	public static byte[] generateEmptyCRL() throws Exception {
		X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(CA_CERTIFICATE.getSubjectX500Principal(), calculateDate(0));

		crlGen.setNextUpdate(calculateDate(24 * 7));

		// add extensions to CRL
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

		crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(CA_CERTIFICATE));

		ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(CA_KEY);

		JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider(BC_PROVIDER);

		return converter.getCRL(crlGen.build(signer)).getEncoded();
	}
}
