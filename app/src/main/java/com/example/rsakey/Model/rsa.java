package com.example.rsakey.Model;
//一、簡介
//        數字簽名用於驗證消息發送者的身份，確保其他人無法僞造身份。
//        二、原理
//        數字簽名基於非對稱加密算法，利用只有擁有者纔有私鑰的特性（這可以標識身份）進行的。
//        1、數字簽名的生成
//        對發送內容先生成有限長度的摘要，再使用私鑰進行加密，進而生成數字簽名。
//        2、數字簽名驗證
//        用公鑰對數字簽名進行解密獲取加密內容（其實也就是摘要），再用與發送方相同的摘要算法對發送內空生成摘要，
//        再將這兩者進行比較，若相等，則驗證成功，否則失敗。

import android.util.Base64;
import android.util.Log;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

public class rsa {
    public static final String KEY_ALGORITHM = "RSA";  //對稱加密
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA"; //簽名算法

    private static final String PUBLIC_KEY = "RSAPublicKey"; //公有key
    private static final String PRIVATE_KEY = "RSAPrivateKey"; //私有key

//Base64是一種能將任意Binary資料用64種字元組合成字串的方法，而這個Binary資料和字串資料彼此之間是可以互相轉換的，十分方便。在實際應用上，Base64除了能將Binary資料可視化之外，也常用來表示資料加密過後的內容。如果要使用Java程式語言來實作Base64的編碼與解碼功
//Base64.decode(String str, int flags)://解密64位元(1,解碼的字串,2.用64位元(回傳byte[] )
//Base64.encodeToString(byte[] input, int flags):(回傳直String )

    //     1.解密64位元方法
    public static byte[] decryptBASE64(String key) {
        return Base64.decode(key, Base64.DEFAULT);//解密64位元(1,解碼的字串,2.用64位元預設的物件)
    }

    //    2.加密64位元方法
    public static String encryptBASE64(byte[] key) {
        return Base64.encodeToString(key, Base64.DEFAULT); //加密(1.加密的byte[] key,2.用64位元預設的物件)
    }


//    KeyFactory.getInstance(String algorithm)//Key工廠.指定的加密算法(RSA)
//    PKCS8EncodedKeySpec(byte[] encodedKey)//將byte[]64編碼轉成PKCS8EncodedKeySpec key規範 (編碼key)
//    Signature.initVerify(PublicKey publicKey)
//    Signature.initSign(PrivateKey privateKey)://初始化簽名(私鑰)
//    Signature.update(byte[] data)://簽名更新(byte[]數據)//    Signature.getInstance(String algorithm)://簽名物件取得從(MD5withRSA)(回傳直 Signature)


    //1.初始化密鑰
//    KeyPairGenerator.getInstance(String algorithm):取得一對鑰使物件實體從(算法Rsa等物件)(回傳直KeyPairGenerator)
//    KeyPairGenerator.initialize(int keysize):設定鑰使長度(int:長度)
//    KeyPairGenerator.generateKeyPair()://取得init後的pairKey(回傳值 KeyPair )
//    KeyPai.getPrivate()://取得公有鑰使(回傳值PrivateKey)
//    KeyPai.getPublic()://取得私有鑰使(回傳直PublicKey)
    public static Map<String, Object> initKey() throws Exception {

        //KeyPairGenerator 初始化設定
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);//取得一對鑰使物件實體從(算法Rsa等物件)(回傳直KeyPairGenerator)
        keyPairGen.initialize(1024);//設定鑰使長度(int:長度)

        //產生一對鑰使
        KeyPair keyPair = keyPairGen.generateKeyPair();//取得init後的pairKey

        //取得公鑰
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();//取得公有鑰使,這邊放入的是 RSAPublicKey

        //取得私鑰
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();//取得私有鑰使,這邊放入的是  RSAPrivateKey

        //鑰使掛上質
        Map<String, Object> keyMap = new HashMap<>();
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PUBLIC_KEY, privateKey);

        return keyMap;
    }

    //取得公鑰(編碼)
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);

        return encryptBASE64(key.getEncoded());
    }

    //取得私鑰(編碼)
    public static String getPrivateKey(Map<String,Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);

        return encryptBASE64(key.getEncoded());
    }


    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       加密数据
     * @param privateKey 私钥
     */
    //用私鑰產生數字簽名
    public static String sign(byte[] data, String privateKey) throws Exception { //(1.加密数据, 2.私鑰)

        // 得到私鑰
        byte[] keyBytes = decryptBASE64(privateKey);  //解密base64編碼的私鑰
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes); //將byte[]64編碼轉成PKCS8EncodedKeySpec (編碼密碼規範
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM); //Key工廠.指定的加密算法(RSA)
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);  //產生私鑰

        //用私鑰對訊息產生數字簽名,訊息加密
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM); //簽名物件取得從(MD5withRSA算法)
        signature.initSign(priKey);//初始化簽名(私鑰)
        signature.update(data);//簽名更新(byte[]數據)

        return encryptBASE64(signature.sign());
    }

    /**
     * 驗證數字簽名
     *
     * @param //data      加密数据
     * @param //publicKey 公钥
     * @param //sign      数字签名
     * @return 校验成功返回true 失败返回false
     * @throws Exception
     */
    //X509EncodedKeySpec(byte[] encodedKey)://將byte[]64編碼轉成X509EncodedKeySpec公鑰key規範 (編碼key)
    //Signatur.initVerify(PublicKey publicKey)://初始化驗證(公有鑰數)
    //keyFactory.generatePublic(KeySpec keySpec)//產生公鑰(回傳PublicKey)
    //Signature.verify(byte[] signature):(回傳值boolean);
    //驗證數字簽名
    public static boolean vetify(byte[] data, String publicKey, String sign) throws Exception {

        //取得公鑰
        byte[] ketBytes = decryptBASE64(publicKey); //解密base64編碼的私鑰取得byte[]
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(ketBytes);//將byte[]64編碼轉成X509EncodedKeySpec公鑰key規範 (編碼key)
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);//Key工廠.指定的加密算法(RSA)
        PublicKey pubkey = keyFactory.generatePublic(keySpec);//產生公鑰(回傳PublicKey)

        //公鑰簽名物件驗證,並更新
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM); //簽名物件取得從(MD5withRSA算法)
        signature.initVerify(pubkey); //初始化驗證(公有鑰數)
        signature.update(data); //簽名物件更新

        return signature.verify(decryptBASE64(sign));//驗證簽名是否正常
    }

    /**
     * 解密<br>
     * 用私钥解密
     *
     * @param //data
     * @param //key
     * @return
     * @throws Exception
     */
    //KeyFactory.getAlgorithm():從key工廠取得演算法(回傳值String)
    //Cipher.getInstance(String transformation)://密碼物件取得從(演算法) (回傳直)Cipher
    //Cipher.doFinal(byte[] input): //執行解密(輸入串流)(回傳直byte[])
    //私密解鑰
    public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception { //(1.輸入串流 2.要解密的鑰使)

        //私鑰解密
        byte[] keyBytes = decryptBASE64(key);

        //取得私鑰
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key prviateKey = keyFactory.generatePrivate(keySpec);

        //數據解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());//密碼物件取得從(演算法)
        cipher.init(Cipher.DECRYPT_MODE, prviateKey);//密碼物件初始化這邊帶入解密模式(1.操作模式,2.Key)
        return cipher.doFinal(data); //執行解密(輸入串流)
    }

    /**
     * 解密<br>
     * 用公钥解密
     *
     * @param //data 1.輸入串流
     * @param //key  2.要解密的鑰使
     * @return
     * @throws Exception
     */
//    用公鑰解密
    public static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {

        //對公鑰解闢
        byte[] keyBytes = decryptBASE64(key);

        //取得公鑰
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(keySpec);

        //對數據解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey); //密碼初始化設定(1,這次用解碼模組,2.公有key)

        return cipher.doFinal(data);
    }

    /**
     * 用公钥加密
     *
     * @param //data
     * @param //key
     * @return
     * @throws Exception
     */
//    用公钥加密
    public static byte[] encryptByPublicKey(byte[] data, String key) throws Exception {//(1.輸入的資訊串流 2.key)

        //對公鑰解密
        byte[] keyBytes = decryptBASE64(key); //Base64.decode(key, Base64.DEFAULT);//解密64位元字串(1,解碼的字串,2.用64位元預設的物件)

        //取得公鑰
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(keySpec);

        //對數據加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);//密碼物件初始化這邊帶入編碼模式(1.操作模式,2.Key)

        return cipher.doFinal(data);
    }

    /**
     * 用私钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
//     用私钥加密
    public static byte[] encryptByPrivateKey(byte[] data, String key)
            throws Exception {
        // 对密钥解密
        byte[] keyBytes = decryptBASE64(key);

        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }


}
