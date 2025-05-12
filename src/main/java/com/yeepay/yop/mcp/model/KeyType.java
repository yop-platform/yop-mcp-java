package com.yeepay.yop.mcp.model;


public class KeyType {

    public static final KeyType MD5 = new KeyType("MD5", 32, null);
    public static final KeyType DSA1024 = new KeyType("DSA", 1024, null);
    public static final KeyType DSA2048 = new KeyType("DSA", 2048, null);
    public static final KeyType RSA4096 = new KeyType("RSA", 4096, "RSA");
    public static final KeyType RSA2048 = new KeyType("RSA", 2048, "RSA");
    public static final KeyType AES256 = new KeyType("AES", 256, null);
    public static final KeyType SM4 = new KeyType("SM4", 128, "EC");
    public static final KeyType SM2 = new KeyType("SM2", 256, "EC");
    private String name;
    private int length;
    private String alg;
    public KeyType(String name, int length, String alg) {

        this.name = name;

        this.length = length;

        this.alg = alg;

    }

    public String getName() {

        return this.name;

    }

    public void setName(String name) {

        this.name = name;

    }

    public int getLength() {

        return this.length;

    }

    public void setLength(int length) {

        this.length = length;

    }

    public String getAlg() {
        return alg;
    }

}
