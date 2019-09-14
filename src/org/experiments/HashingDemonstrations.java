package org.experiments;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class HashingDemonstrations  {
    // This method mandatoryily accepts 3 arguments -
    // first one is the input string (to be hashed),
    // second one is the algo name which can be MD5/SHA-1/SHA-256/SHA-384/SHA-512
    // third one is a boolean indicating whether the algo needs to be salted

    // Typical example inputs to this method :
    // password SHA-256 true
    // password SHA-512 false
    public static void main(String[] args) throws Exception {
        if (null == args[0]) throw new Exception("Please provide an input content as the first argument");
        if (null == args[1]) throw new Exception("Please provide an algorithm name as the second argument. Normally it is MD5 or SHA-1 or SHA-256 or SHA-384 or SHA-512");
        if (null == args[2]) throw new Exception("Please provide your input on whether you want to add salt or not, if salted - then use yes else use no");

        String inputContent =args[0];
        String hashingAlgorithmName= args[1];
        boolean isSalted = Boolean.valueOf(args[2]);

        byte[] hashedBytes = getHashedBytes(hashingAlgorithmName, inputContent, isSalted);
        String hashedHexOutput = getHashedHexOutput(hashedBytes);
        System.out.println("Input content: "+inputContent+", Hashing Algo: "+hashingAlgorithmName + ", Salted: "+isSalted+", HashedHexOutput: "+hashedHexOutput);

    }

    private static byte[] getHashedBytes (String hashingAlgorithmName, String inputContent, boolean isSalted) {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(hashingAlgorithmName);
            if (isSalted){
                messageDigest.update(getSalt());
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return messageDigest.digest(inputContent.getBytes());
    }

    private static String getHashedHexOutput(byte[] hashedBytes){
        StringBuilder hashedOutputBuilder = new StringBuilder();
        for(int iCount=0; iCount< hashedBytes.length ;iCount++)
        {
            hashedOutputBuilder.append(Integer.toString((hashedBytes[iCount] & 0xff) + 0x100, 16).substring(1));
        }
        return hashedOutputBuilder.toString();
    }

    private static byte[] getSalt() throws NoSuchAlgorithmException
    {
        SecureRandom secureRandomInstance = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        secureRandomInstance.nextBytes(salt);
        return salt;
    }

}
