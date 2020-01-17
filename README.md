# Java 8 Features
This project gives a simple overview of features in Java8 and it is mainly to help my students who are new to Java8.
This repository contains some simple programs divided into 4 different packages to demonstrate the following 4 new features introduced in Java 8 :
* Default and static methods in Interfaces
* Optional
* Lambdas
* Streams


Please also refer to my blog here [Soumik's blog](https://msoumik78.github.io/java/2019/05/10/java-8-features.html)


### Dependencies

* Java 8 should be installed and available in the system. JAVA_HOME environment variable should be set and pointing to the location of Java 8.
* Maven should be installed in the system and set in PATH.

### Compiling

 `mvn clean compile `

### Running program

The below command runs the program related to default and static methods in Java 8 interfaces     
`mvn exec:java -Dexec.mainClass="defaultAndStaticMethods.VehicleImpl" `

The below command runs the program related to Lambdas in Java 8      
`mvn exec:java -Dexec.mainClass="lambdas.Java8LambdasDemo" `

The below command runs the program related to Lambdas in Java 8     
`mvn exec:java -Dexec.mainClass="optional.Java8Optional" `

The below command runs the program related to Lambdas in Java 8      
`mvn exec:java -Dexec.mainClass="streams.Java8Streams" `

