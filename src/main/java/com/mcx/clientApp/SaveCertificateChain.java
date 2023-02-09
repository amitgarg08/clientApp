package com.mcx.clientApp;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;

public class SaveCertificateChain {

	public static void main(String[] args) throws Exception, IOException {
		String configName = "src/main/resources/pkcs11.cfg";
		Provider providerPKCS11 = Security.getProvider("SunPKCS11");
		providerPKCS11 = providerPKCS11.configure(configName);
		Security.addProvider(providerPKCS11);

		String pin = "123456789";
		java.security.KeyStore keyStore = KeyStore.getInstance("PKCS11", providerPKCS11);
		keyStore.load(null, pin.toCharArray());
		java.util.Enumeration<String> aliases = keyStore.aliases();
		String alias = null;
		while (aliases.hasMoreElements()) {
			alias = aliases.nextElement();
			System.out.println(alias);
		}
		Certificate[] chain = keyStore.getCertificateChain(alias);

		try {

			FileOutputStream fileOut = new FileOutputStream("src/main/resources/certificate.ser");
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			out.writeObject(chain);
			out.close();
			fileOut.close();
			System.out.printf("Serialized data is saved in /tmp/employee.ser");
		} catch (IOException i) {
			i.printStackTrace();
		}

		try {
			Certificate[] e;
			FileInputStream fileIn = new FileInputStream("src/main/resources/certificate.ser");
			ObjectInputStream in = new ObjectInputStream(fileIn);
			e = (Certificate[]) in.readObject();
			in.close();
			fileIn.close();
		} catch (IOException i) {
			i.printStackTrace();
			return;
		} catch (ClassNotFoundException c) {
			System.out.println("Certificate not found");
			c.printStackTrace();
			return;
		}
	}
}
