package com.mcx.clientApp;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;
import java.security.GeneralSecurityException;

public class ServerSignature implements IExternalSignature {

	@Override
	public String getHashAlgorithm() {
		return DigestAlgorithms.SHA256;
	}

	@Override
	public String getEncryptionAlgorithm() {
		return "RSA";
	}

	public byte[] sign(byte[] sh) throws GeneralSecurityException {
		ExternalSignatureService externalService = SpringContext.getBean(ExternalSignatureService.class);
		// Back-end service call
		byte[] extSignature = externalService.signedHash(sh);
		return extSignature;
	}

}