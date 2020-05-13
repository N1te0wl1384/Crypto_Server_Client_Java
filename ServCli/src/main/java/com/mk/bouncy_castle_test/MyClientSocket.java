package com.mk.bouncy_castle_test;

import org.bouncycastle.cms.CMSException;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;

public class MyClientSocket {

    private static Encrypt e  = new Encrypt();
    private Socket socket;
    private Scanner scanner;
    private static PrivateKey pk;
    private X509Certificate serverCert;

    private MyClientSocket(InetAddress serverAddress, int serverPort) throws Exception {
        this.socket = new Socket(serverAddress, serverPort);
        this.scanner = new Scanner(System.in);
    }

    private void start() throws IOException, CMSException, CertificateException, ClassNotFoundException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        String message;
        byte[] encryptedMessage;

        while (true) {
            String data = null;
            message = scanner.nextLine();
            encryptedMessage = e.encryptData(message.getBytes(), serverCert);
            OutputStream out = new DataOutputStream(this.socket.getOutputStream());
            out.write(encryptedMessage);
            out.flush();
            DataInputStream ois = new DataInputStream(socket.getInputStream());
            String incomingMessage = e.decryptionHandler(pk, ois);
            System.out.println("Message: " + incomingMessage);
        }
    }

    public void init(X509Certificate cert) throws CertificateException, IOException {
        OutputStream out = new DataOutputStream(this.socket.getOutputStream());
        DataInputStream in = new DataInputStream(this.socket.getInputStream());
        e.pushCert(cert, out);
        System.out.println(in.readUTF());
        serverCert = e.getCert(in);
    }

    public static void main(String[] args) throws Exception {
        CryptoTest certFactory = new CryptoTest();
        X509Certificate cert = certFactory.provideCertificate("password", "password");
        pk = e.initializeKeystore("password".toCharArray(), "password".toCharArray(), "C:\\Users\\Marek\\Desktop\\2020-02-21-Tomek\\ServerProxy\\src\\main\\java\\com\\ubivault\\bouncy_castle_test\\identity.p12");
        MyClientSocket client = new MyClientSocket(
                InetAddress.getByName("192.168.0.101"),
                Integer.parseInt("6060"));
        client.init(cert);
        System.out.println("\r\nConnected to Server: " + client.socket.getInetAddress());
        client.start();
    }
}
