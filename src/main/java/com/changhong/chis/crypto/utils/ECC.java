package com.changhong.chis.crypto.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * @author ：hdj
 * @date ：Created in 2/4/21 5:41 PM
 * @description：
 * @modified By：
 * @version: $
 */
public class ECC {


    private static String EC_ALGORITHM="EC";
    private static String EC_PROVIDER="BC";

    /**
     * 生成密钥对
     *
     * @param keysize 密钥长度
     * @return
     */
    public static KeyPair generateECCKeyPair(int keysize) {
        try {
            // 获取指定算法的密钥对生成器
            KeyPairGenerator generator = KeyPairGenerator.getInstance(EC_ALGORITHM, EC_PROVIDER);
            // 初始化密钥对生成器（指定密钥长度, 使用默认的安全随机数源）
            generator.initialize(keysize);
            // 随机生成一对密钥（包含公钥和私钥）
            return generator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
