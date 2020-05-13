package com.mk.bouncy_castle_test;
import java.net.*;
import java.util.Arrays;
import java.io.*;

public class ClientTest {
    // initialize socket and input output streams
    private Socket socket = null;
    private OutputStream out = null;
    private InputStream in = null;

    // constructor to put ip address and port
    public ClientTest(String address, int port) {
        // establish a connection
        try {
            socket = new Socket(address, port);
            if (socket.isConnected()) {
                System.out.println("Connected");
            }

            // sends output to the socket
            out = new DataOutputStream(socket.getOutputStream());
            //takes input from socket
            in = new DataInputStream(socket.getInputStream());
        } catch (UnknownHostException u) {
            System.out.println(u);
        } catch (IOException i) {
            System.out.println(i);
        }


        try {
            byte[] arr = {(byte)0x00, (byte)0x01, (byte)0x00, (byte)0x10, (byte)0x00, (byte)0x01,
                    (byte)0x00, (byte)0x1F, (byte)0x60, (byte)0x1D, (byte)0xA1, (byte)0x09,
                    (byte)0x06, (byte)0x07, (byte)0x60, (byte) 0x85, (byte)0x74, (byte)0x05,
                    (byte) 0x08, (byte)0x01, (byte)0x01, (byte)0xBE, (byte)0x10, (byte)0x04,
                    (byte)0x0E, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x06,
                    (byte)0x5F, (byte)0x1F, (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x18,
                    (byte)0x1D, (byte)0xFF, (byte)0xFF};

            // sending data to server
            out.write(arr);

            String req = Arrays.toString(arr);
            //printing request to console
            System.out.println("Sent to server : " + req);

            // Receiving reply from server
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte buffer[] = new byte[1024];
            baos.write(buffer, 0 , in.read(buffer));

            byte result[] = baos.toByteArray();

            String res = Arrays.toString(result);

            // printing reply to console
            System.out.println("Recieved from server : " + res);
        } catch (IOException i) {
            System.out.println(i);
        }
        // }

        // close the connection
        try {
            // input.close();
            in.close();
            out.close();
            socket.close();
        } catch (IOException i) {
            System.out.println(i);
        }
    }

    public static void main(String args[]) {
        new ClientTest("127.0.0.1", 5000);
    }
}
