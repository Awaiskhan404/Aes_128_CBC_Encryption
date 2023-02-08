import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.UUID;



class CryptoGraphyMngr {
     
    public static String ALGORITHM = "AES";
    private static String AES_CBS_PADDING = "AES/CBC/PKCS5Padding";
 
    public static byte[] encrypt(final byte[] key, final byte[] IV, final byte[] message) throws Exception {
        return CryptoGraphyMngr.encryptDecrypt(Cipher.ENCRYPT_MODE, key, IV, message);
    }
 
    public static byte[] decrypt(final byte[] key, final byte[] IV, final byte[] message) throws Exception {
        return CryptoGraphyMngr.encryptDecrypt(Cipher.DECRYPT_MODE, key, IV, message);
    }
 
    private static byte[] encryptDecrypt(final int mode, final byte[] key, final byte[] IV, final byte[] message)
            throws Exception {
        final Cipher cipher = Cipher.getInstance(AES_CBS_PADDING);
        final SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        final IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(mode, keySpec, ivSpec);
        return cipher.doFinal(message);
    }
}

public class Aes_128_CBC_Encryption {

        private static int AES_128 = 128;

        public static void main(String[] args) throws Exception {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoGraphyMngr.ALGORITHM);
                keyGenerator.init(AES_128);
                //Generate Key
                SecretKey key = keyGenerator.generateKey();
                //Initialization vector
                SecretKey IV = keyGenerator.generateKey();
                /*
                 * @param randomString
                 * you can add your own string to encrypt or decrypt here
                 */
                String randomString = UUID.randomUUID().toString().substring(0,
                                16);
                System.out.println("1. Message to Encrypt: " + randomString);

                byte[] cipherText = CryptoGraphyMngr.encrypt(key.getEncoded(),
                                IV.getEncoded(), randomString.getBytes());
                System.out.println("2. Encrypted Text: " +
                                Base64.getEncoder().encodeToString(cipherText));

                byte[] decryptedString = CryptoGraphyMngr.decrypt(key.getEncoded(),
                                IV.getEncoded(), cipherText);
                System.out.println("3. Decrypted Message : " + new String(decryptedString));
        }
}