package com.chislab.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * @author lpf
 * @create 2021-02-05 上午9:36
 */
public class EccUtils {
    public static KeyPair generateEccKeyPair() throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        // add provider
        Security.addProvider(new BouncyCastleProvider());

        // generate key pair
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return keyPair;
    }

    /**
     *
     * @param publicKey
     * @param plainText
     * @return Base64 encoding string
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String eccEncrypt(PublicKey publicKey, String plainText) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        final Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        final byte[] bytes = cipher.doFinal(plainText.getBytes());

        return Base64.toBase64String(bytes);
    }

    public static String eccDecrypt(PrivateKey privateKey, String cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        final Cipher cipher = Cipher.getInstance("ECIES");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        final byte[] bytes = cipher.doFinal(Base64.decode(cipherText));

        return new String(bytes);
    }
}
