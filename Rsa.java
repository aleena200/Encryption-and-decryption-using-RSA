import Pack1.Myclass;
import Pack2.Decrypt;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

public class Rsa implements ActionListener {

    JFrame f;
    JTextField j1, j2, j3;
    JButton b0, b1;
    String r = "";
    byte[] encryptedMessage; // Declare encryptedMessage here
	KeyPair keyPair;
    Rsa() {
    
    try
        {
        	keyPair = generateKeyPair();
        }
        catch(Exception e)
        {
        	System.out.println(e);
        }

    
    
        f = new JFrame("ENCRYPTION-DECRYPTION");
        j1 = new JTextField();
        j2 = new JTextField();

        f.add(j1);

        f.setSize(600, 600);
        f.setLayout(new GridLayout(7, 7, 10, 10));

        b0 = new JButton("ENCRYPT");
        b1 = new JButton("DECRYPT");

        f.add(b0);
        f.add(b1);
        f.add(j2);

        b0.addActionListener(this);
        b1.addActionListener(this);

        f.setVisible(true);
        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        
    }

    public void actionPerformed(ActionEvent e) {

        if (e.getSource() == b0) {
            try {
                String s = j1.getText();

                // Generate Key Pair
                if(keyPair!=null)
                {

                // Get public and private keys
                PublicKey publicKey = keyPair.getPublic();
               // PrivateKey privateKey = keyPair.getPrivate();

                // Encryption
                encryptedMessage = encrypt(s, publicKey);
                //System.out.println(encryptedMessage);
                r = r + bytesToHex(encryptedMessage);
                j2.setText("" + r);
                }
                else
                System.out.println("Error");

            } catch (Exception e1) {
                System.out.println(e1);
            }

        } else if (e.getSource() == b1) {
            try {
             String s = j2.getText();
             if(keyPair!=null)
                {
             
                // Generate Key Pair
                //KeyPair keyPair = generateKeyPair();

                // Get public and private keys
                //PublicKey publicKey = keyPair.getPublic();
               PrivateKey privateKey = keyPair.getPrivate();

                // Decryption
                Decrypt d = new Decrypt();
                String decryptedMessage = d.decrypt(encryptedMessage, privateKey);
                //r = r + decryptedMessage;
                //System.out.println(r);
                j2.setText("" + decryptedMessage);
                }
                else
                System.out.println("Error");

            } catch (Exception e1) {
                System.out.println(e1);
            }
        }
    }

    public static void main(String args[]) {
        Rsa r = new Rsa();
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512); // Key size
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    private static byte[] encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte aByte : bytes) {
            result.append(String.format("%02x", aByte));
        }
        return result.toString();
    }
    public static String decrypt(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
    
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
cipher.init(Cipher.DECRYPT_MODE, privateKey);

       // Cipher cipher = Cipher.getInstance("RSA");
       // cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        String s=new String(decryptedBytes); //converting byte array to string
        return s;
        //return new String(decryptedBytes);
    }
}

