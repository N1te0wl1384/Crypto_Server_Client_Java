package com.mk.bouncy_castle_test;

import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.OutputEncryptor;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

public class Encrypt {

    public static byte[] encryptData(byte[] data,
                                     X509Certificate encryptionCertificate)
            throws CertificateEncodingException, CMSException, IOException {

        byte[] encryptedData = null;
        if (null != data && null != encryptionCertificate) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator
                    = new CMSEnvelopedDataGenerator();

            JceKeyTransRecipientInfoGenerator jceKey
                    = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
            CMSTypedData msg = new CMSProcessableByteArray(data);
            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator
                    .generate(msg, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
                            .setProvider("BC").build());
            encryptedData = cmsEnvelopedData.getEncoded();
        }
        return encryptedData;
    }

    public static byte[] decryptData(
            byte[] encryptedData,
            PrivateKey decryptionKey)
            throws CMSException {

        byte[] decryptedData = null;
        if (null != encryptedData && null != decryptionKey) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

            Collection<RecipientInformation> recipients
                    = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo
                    = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient
                    = new JceKeyTransEnvelopedRecipient(decryptionKey);

            return recipientInfo.getContent(recipient);
        }
        return decryptedData;
    }

    public X509Certificate getCert(InputStream ois) throws IOException, CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte buffer[] = new byte[2048];
        baos.write(buffer, 0, ois.read(buffer));
        byte[] byteCert = baos.toByteArray();
        ByteArrayInputStream bais = new ByteArrayInputStream(byteCert);
        X509Certificate cert = (X509Certificate)certificateFactory.generateCertificate(bais);
        System.out.println("Certificate obtained");
        return cert;
    }

    public void pushCert(X509Certificate cert, OutputStream out) throws CertificateException, IOException {
        byte[] certArray = cert.getEncoded();
        out.write(certArray);
        out.flush();
        System.out.println("Certificate sent");
    }

    public String decryptionHandler(PrivateKey key, InputStream is) throws KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, CMSException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        baos.write(buffer, 0, is.read(buffer));
        byte[] encryptedMessage = baos.toByteArray();
        byte[] decryptedMessage = decryptData(encryptedMessage, key);
        return new String(decryptedMessage);
    }


    // make this method more generic
    public PrivateKey initializeKeystore(char[] keystorePass, char[] keyPass, String keystorePath) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream(keystorePath), keystorePass);
        PrivateKey key = (PrivateKey) keystore.getKey("mykey", keyPass);
        return  key;
    }

}
