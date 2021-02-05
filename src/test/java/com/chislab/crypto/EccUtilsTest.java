package com.chislab.crypto;

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * @author lpf
 * @create 2021-02-05 上午9:51
 */
public class EccUtilsTest {

    @Test
    public void testEccUtils() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {
        final KeyPair keyPair = EccUtils.generateEccKeyPair();
        final PublicKey publicKey = keyPair.getPublic();
        final PrivateKey privateKey = keyPair.getPrivate();

        final String cipherText = EccUtils.eccEncrypt(publicKey, "Hello Chislab");
        final String plainText = EccUtils.eccDecrypt(privateKey, cipherText);

        Assert.assertTrue("Hello Chislab".equals(plainText));
    }
}
