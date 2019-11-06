# RSA Encrypted Properties Extension - Properties Encryptor

A custom standalone jar has been provided which helps encrypt the properties key values using the keystore created. This may be uploaded to Exchange as well , for easy access for the customer.



## Create the Encryption JAR
1. Download the Project Source Code
2. Navigate to the Project Folder
3. Execute the below command to create the Encryption JAR:

```
mvn clean package
```
4. Ensure the command executes successfully , and you get rsa-utilities-0.1.0.jar in target folder

## Generate a keystore
Sample command to create a keystore is provided below:

```
keytool -genkeypair -alias {{keyAlias}} -storepass {{keyStorePassword}} -keypass {{keyPassword}} -keyalg RSA -keystore {{keyStoreName}.jks
```
where , {{Value}} are placeholders to be replaced by specific values

## Encrypt each property key value:

```
java -jar rsa-utilities-0.1.0.jar encrypt {{string}} {(fully qualified path}}/{{keyStoreName}.jks {{keyStorePassword}} {{keyPassword}} {{keyAlias}}
```
where , {{Value}} are placeholders to be replaced by specific values


