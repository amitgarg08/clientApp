package com.mcx.clientApp;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.CertificateUtil;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.TSAClientBouncyCastle;

public class SignWithPKCS11USB {

	public static final String DEST = "target/";
	public static final String SRC = "src/main/resources/sample.pdf";
	public static final String[] RESULT_FILES = new String[] { "signed_token.pdf" };

	public void initSign() throws IOException, GeneralSecurityException {
		String configName = "src/main/resources/pkcs11.cfg";
		Provider providerPKCS11 = Security.getProvider("SunPKCS11");
		providerPKCS11 = providerPKCS11.configure(configName);
		Security.addProvider(providerPKCS11);

		BouncyCastleProvider providerBC = new BouncyCastleProvider();
		Security.addProvider(providerBC);

		// Get provider KeyStore and login with PIN
		//String pin = "123456789";
		
		Certificate[] e = null;
		try {
			FileInputStream fileIn = new FileInputStream("src/main/resources/certificate.ser");
			ObjectInputStream in = new ObjectInputStream(fileIn);
			e = (Certificate[]) in.readObject();
			in.close();
			fileIn.close();
		} catch (IOException i) {
			i.printStackTrace();
			return;
		} catch (ClassNotFoundException c) {
			System.out.println("Employee class not found");
			c.printStackTrace();
			return;
		}

		Certificate[] chain = e;
		IOcspClient ocspClient = new OcspClientBouncyCastle(null);
		ITSAClient tsaClient = null;
		for (int i = 0; i < chain.length; i++) {
			X509Certificate cert = (X509Certificate) chain[i];
			String tsaUrl = CertificateUtil.getTSAURL(cert);
			if (tsaUrl != null) {
				tsaClient = new TSAClientBouncyCastle(tsaUrl);
				break;
			}
		}

		List<ICrlClient> crlList = new ArrayList<ICrlClient>();
		crlList.add(new CrlClientOnline(chain));
		sign(SRC, DEST + RESULT_FILES[0], chain, DigestAlgorithms.SHA256, providerPKCS11.getName(),
				PdfSigner.CryptoStandard.CMS, "Test", "Ghent", crlList, ocspClient, tsaClient, 0);

	}

	public void sign(String src, String dest, Certificate[] chain, String digestAlgorithm, String provider,
			PdfSigner.CryptoStandard subfilter, String reason, String location, Collection<ICrlClient> crlList,
			IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize)
			throws GeneralSecurityException, IOException {
		PdfReader reader = new PdfReader(src);
		PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

		// Create the signature appearance
		Rectangle rect = new Rectangle(336, 348, 200, 100);
		PdfSignatureAppearance appearance = signer.getSignatureAppearance();
		appearance.setReason(reason).setLocation(location)

				// Specify if the appearance before field is signed will be used
				// as a background for the signed field. The "false" value is the default value.
				.setReuseAppearance(false).setPageRect(rect).setPageNumber(1);
		signer.setFieldName("sig");

		// IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm,
		// provider);
		IExternalSignature pks = new ServerSignature();
		IExternalDigest digest = new BouncyCastleDigest();

		// Sign the document using the detached mode, CMS or CAdES equivalent.
		signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
	}

}
