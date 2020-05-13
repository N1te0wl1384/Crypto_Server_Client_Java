package com.mk.bouncy_castle_test;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CryptoTest {
    PrivateKey key;
    X509Certificate certificate;
    Encrypt e = new Encrypt();

    public X509Certificate provideCertificate(String keystorePass, String keyPass){

        Security.addProvider(new BouncyCastleProvider());

        char[] keystorePassword = keystorePass.toCharArray();
        char[] keyPassword = keyPass.toCharArray();

        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new FileInputStream("C:\\Users\\Marek\\Desktop\\2020-02-21-Tomek\\ServerProxy\\src\\main\\java\\com\\ubivault\\bouncy_castle_test\\identity.p12"), keystorePassword);
            key = (PrivateKey) keystore.getKey("cakey", keyPassword);

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
            certificate = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream("C:\\Users\\Marek\\Desktop\\2020-02-21-Tomek\\ServerProxy\\src\\main\\java\\com\\ubivault\\bouncy_castle_test\\cacert.cer"));
            return certificate;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void handleMessageEncryption(String message) throws CMSException, IOException, CertificateEncodingException {
        System.out.println("Original Message : " + message);
        byte[] stringToEncrypt = message.getBytes();
        byte[] encryptedData = e.encryptData(stringToEncrypt, certificate);
        System.out.println("Encrypted Message : " + new String(encryptedData));
        byte[] rawData = e.decryptData(encryptedData, key);
        String decryptedMessage = new String(rawData);
        System.out.println("Decrypted Message : " + decryptedMessage);
    }

    public byte[] handleCert(byte[] cert ) throws IOException {
        ByteArrayInputStream br = new ByteArrayInputStream(cert);

        int bytesRead = 0;
        int b;
        while ((b = br.read()) != -1) {
            cert[bytesRead++] = (byte)b;
        }

        br.close();
        return cert;
    }

    public byte[] writeCert(InputStream inputStream) throws IOException {
        byte[] userCert;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int b;

        while ((b = inputStream.read()) != -1) {
            bos.write(buffer, 0, b);
        }
        bos.close();

        return bos.toByteArray();
    }

    public X509Certificate getCert(){ return certificate; }

    public PrivateKey getPrivateKey(){ return key; }
}
