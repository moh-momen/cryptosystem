import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Scanner;

public class EncDec {
    private static String initVector;
    private static Key key;
    private static final String characterEncoding = "UTF-8";
    private final String PADDING_SCHEME = "PKCS5Padding";

    private final String Method;
    private final String Mode;
    byte[] ivBytes = new byte[8];
    private final String keystring;
    String transformation;

    public EncDec(String key, String iv, String method, String mode) {
        this.ivBytes = iv.getBytes();
        this.Method = method;
        this.Mode = mode;
        this.keystring = key;
        this.initVector = iv;
        this.key = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), Method);
        transformation = String.format("%s/%s/%s", Method, Mode, PADDING_SCHEME);
    }

    public String encryptDES(String valueToEncrypt) throws Exception {
        Cipher instance = Cipher.getInstance(transformation);
        instance.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
        byte[] bytes = instance.doFinal(String.format("12345678%s", valueToEncrypt).getBytes());
        return Base64.getEncoder().encodeToString(bytes);
    }

    public String decryptDES(String encryptedValue) throws Exception {
        transformation = String.format("%s/%s/%s", Method, Mode, PADDING_SCHEME);
        Cipher instance = Cipher.getInstance(transformation);
        instance.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
        byte[] bytes = instance.doFinal(Base64.getDecoder().decode(encryptedValue));
        return new String(bytes, StandardCharsets.UTF_8).substring(8);
    }

    public byte[] encryptAES(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(characterEncoding));

            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encode(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public String decryptAES(byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(characterEncoding));
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    static String generateIv(int n) {
        StringBuilder randomKey = new StringBuilder();
        for (int i = 0; i < n; i++) {
            if ((int) (Math.random() * randomKey.length()) * i % 3 == 0) {
                randomKey.append("1");
            } else {
                randomKey.append("0");
            }
        }
//        System.out.println(randomKey);
        return randomKey.toString();
    }


    private static String readInputFile(String fileName) throws FileNotFoundException {
        fileName = "src/" + fileName;
        File inputFile = new File(fileName);
        Scanner in = new Scanner(inputFile);
        String plaintext = "";
        while (in.hasNextLine()) {
            plaintext = plaintext + in.nextLine() + "\n";
        }

        return plaintext;
    }

    private static void easEncDec(String fileName, String plaintext, String inputKey) throws IOException {
        String key = inputKey.substring(0, 8);
        EncDec aesOFB = new EncDec(key, generateIv(8), "DES", "OFB");

        byte[] encryptedString = aesOFB.encryptAES(plaintext);
        System.out.println("Done, file " + fileName + " is encrypted using AES");

        FileWriter witter = new FileWriter("encryptTextAES.txt");
        witter.write(new String(encryptedString));
        witter.close();

        String decryptedString = aesOFB.decryptAES(encryptedString);
//        System.out.println("After decryption - " + decryptedString);
        FileWriter witterOutput = new FileWriter("decryptedTextAES.txt");
        witterOutput.write(new String(decryptedString));
        witterOutput.close();
        System.out.println("Done, file " + fileName + " is decrypted using AES");


    }

    private static void desEncDec(String fileName, String plaintext, String inputKey) throws Exception {
        String key = inputKey.substring(0, 8);

        EncDec des = new EncDec(key, generateIv(8), "DES", "OFB");
        String desEncryption = des.encryptDES(plaintext);
        System.out.println("Done, file " + fileName + " is encrypted using DES");

        FileWriter witter = new FileWriter("encryptTextDES.txt");
        witter.write(new String(desEncryption));
        witter.close();

//        System.out.println(desEncryption);
        String desDecryption = des.decryptDES(desEncryption);
//        System.out.println(desDecryption);
        FileWriter witterOutput = new FileWriter("decryptedTextDES.txt");
        witterOutput.write(desDecryption);
        witterOutput.close();

        System.out.println("Done, file " + fileName + " is decrypted using DES");

    }

    private static String textToBinary(String key) {
//        key = key.substring(0,24);
        if (key.length() >= 8) {
            StringBuilder result = new StringBuilder();
            char[] chars = key.toCharArray();
            for (char aChar : chars) {
                result.append(
                        String.format("%8s", Integer.toBinaryString(aChar))   // char -> int, auto-cast
                                .replaceAll(" ", "0")                         // zero pads
                );
            }
//            System.out.println(result.toString().length());
            return result.toString();
        } else System.out.println("Please Enter key with just 192 for AES or 64 for DES");

        return "";


    }

    public static void main(String[] args) throws Exception {
      /*  Here let's take inputs:
            file name,
            Algorithm,
            key
      */

        System.out.println("                         A SYMMETRIC CRYPTO SYSTEM");
        System.out.println("=================================================================================");
        System.out.println("MAIN MENU");
        System.out.println("----------------------");
        System.out.println("1. Encrypt");
        System.out.println("2. Decrypt");
        System.out.println("3. Exit");
        System.out.println("----------------------");
        Scanner in = new Scanner(System.in);
        int input = 1;

        while (input != 3) {
            System.out.print("Enter your choice: ");
            input = in.nextInt();

            if (input == 1 || input == 2) {
                System.out.print("Name: ");
                String fileName = in.next();
                System.out.print("Algorithm(DES, AES): ");
                String algorithm = in.next();
                System.out.println("Pleas enter the key");
                String inputKey = textToBinary(in.next());
//                System.out.println(fileName + " " + algorithm + " " + inputKey);
                String plaintext = readInputFile(fileName);

//                System.out.println(plaintext);

                if (algorithm.equals("DES")) {
                    desEncDec(fileName, plaintext, inputKey);

                } else if (algorithm.equals("AES")) {
                    easEncDec(fileName, plaintext, inputKey);

                } else System.out.println("please, Select either DES or AES algorithm!");


            }

            else  if (input ==3){
                System.out.println("Exit");

            }

            else
                System.out.println("Please Enter number 1,2 3");
        }


    }


}