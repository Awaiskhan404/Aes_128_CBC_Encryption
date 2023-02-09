import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import javax.crypto.Cipher;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Base64;
import java.util.Arrays;

public class AesKeyFinder {
    public static void findKey(String plainTextFile, String cipherTextFile, String ivFile, String keyFile) throws Exception {
        byte[] plaintext = readBytesFromFile(plainTextFile);
        byte[] ciphertext = readBytesFromFile(cipherTextFile);
        byte[] iv = readBytesFromFile(ivFile);

        byte[] key = new byte[16];
        byte[] block1 = Arrays.copyOfRange(plaintext, 0, 16);
        byte[] block2 = Arrays.copyOfRange(ciphertext, 0, 16);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decryptedBlock2 = cipher.doFinal(block2);

        for (int i = 0; i < 16; i++) {
            key[i] = (byte)(block1[i] ^ decryptedBlock2[i]);
        }

        writeKeyToFile(keyFile, key);
    }

    private static byte[] readBytesFromFile(String fileName) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String base64Encoded = reader.readLine();
        reader.close();
        return Base64.getDecoder().decode(base64Encoded);
    }

    private static void writeKeyToFile(String fileName, byte[] key) throws Exception {
        BufferedWriter writer = new BufferedWriter(new FileWriter(fileName));
        writer.write("-----BEGIN AES 128-BIT KEY-----\n");
        writer.write(Base64.getEncoder().encodeToString(key));
        writer.write("\n-----END AES 128-BIT KEY-----");
        writer.close();
    }
}



/*
@injectable(__class__)
 * Algorithm requires IV Vector to be provided. Otherwise we need to use brute force to find the key with takes 2^128 time.
 */