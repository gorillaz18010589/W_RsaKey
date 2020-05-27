package com.example.rsakey;
//1.建立Rsa bean
//2,宣告三個痊癒變數publicKey,privateKey,encodeData,並且產生get跟setter方法(getPublicKey跟)

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;

import com.example.rsakey.Model.rsa;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Map;

public class MainActivity extends AppCompatActivity {
    EditText edtInput, edtOutput;
    private String publicKey = "";
    private String privateKey = "";
    private byte[] encodeData = null;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        edtInput = findViewById(R.id.edtInput);
        edtOutput = findViewById(R.id.edtOutput);

        try {
            //1.取得公私鑰
            Map<String, Object> keyMap = rsa.initKey(); //產生一對鑰使
            privateKey = rsa.getPrivateKey(keyMap); //取得私鑰
            publicKey = rsa.getPublicKey(keyMap); //取得公鑰
        } catch (Exception e) {
            e.printStackTrace();
        }
        Log.v("hank", "取得公私鑰:" + privateKey + "," + publicKey);
    }

    //1.按下按鈕進行編碼
    //BigInteger(int signum, byte @NonNull [] magnitude)
    public void encrypt(View view) throws  Exception{
        String publicKey = getPublicKey(); //取得publicKey現在的質
        byte[] rsaData = edtInput.getText().toString().getBytes(); //將輸入的資訊,轉成byte[]串流

            //將你輸入的資訊,用公鑰編碼
            rsa.encryptByPublicKey(rsaData, publicKey);
            String encodeStr = new BigInteger(1,encodeData).toString();
            edtOutput.setText("2");
            Log.v("hank","2");


        Log.v("hank","encrypt");
    }

    //1.按下按鈕進行解碼
    public void decrypt(View view) {
    }


    //2.getBean方法,因為要拿到區域變數的質,所以自己寫方法取得質
    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

}
