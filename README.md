# Hashing and Encryption
This project gives a simple overview of the following 2 fundamental aspects of digital Security
* Hashing
* Encryption

Please refer to my blog here [Soumik's blog on hashing and encryption](https://msoumik78.github.io/digitalsecurity/2019/03/15/basics-of-digital-security.html)


### Dependencies

* Java 8 should be installed and available in the system. JAVA_HOME environment variable should be set and pointing to the location of Java 8.
* Maven should be installed in the system and set in PATH.

### Compiling

 `mvn clean compile `

### Running program

The below command runs the hashing program with 3 inputs (note that the program expects 3 inputs - where the first one is the input which will be hashed, second is the hashing algorithm name and third is true/false depending on whether you want to salt the hashing to make it stronger )     
`mvn exec:java -Dexec.mainClass="hashing.HashingDemonstrations"  -Dexec.args="password SHA-256 true"  `


The below command runs the symmetric encryption program with 1 input which is the content to be encrypted ("password" in this case)          
`mvn exec:java -Dexec.mainClass="encryption.SymmetricEncryptionDemonstration" -Dexec.args="password"`

The below command runs the symmetric encryption program with 1 input which is the content to be encrypted ("password" in this case)    
`mvn exec:java -Dexec.mainClass="encryption.AsymmetricEncryptionDemonstration" -Dexec.args="password" `
