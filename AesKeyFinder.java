import java.io.BufferedReader;
import java.io.FileReader;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class AesKeyFinder {
    public static byte[] findKey(String plainTextFile, String cipherTextFile, String ivFile) throws Exception {
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

        return key;
    }

    private static byte[] readBytesFromFile(String fileName) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String base64Encoded = reader.readLine();
        reader.close();
        return Base64.getDecoder().decode(base64Encoded);
    }
}


/*
 * Algorithm requires IV Vector to be provided. Otherwise we need to use brute force to find the key with takes 2^128 time.
 */