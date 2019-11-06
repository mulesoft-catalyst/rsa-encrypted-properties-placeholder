package com.mulesoft.ps.apac.sdk.encrypted.properties.api;

import java.security.KeyPair;
import java.util.Optional;
import java.util.Properties;

import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.config.api.dsl.model.ResourceProvider;
import org.mule.runtime.config.api.dsl.model.properties.ConfigurationProperty;
import org.mule.runtime.config.api.dsl.model.properties.DefaultConfigurationPropertiesProvider;

public class EncryptedPropertiesProvider extends DefaultConfigurationPropertiesProvider {
	
	private final static String RSA_ENC_PREFIX = "rsaEncrypt::";
	private final static Properties props  = new Properties();
	private String file;
	private String keystorePath;
	private String keystorePass;
	private String keyPass;
	private String keyAlias;
	String decryptedValue = null;
	
	public EncryptedPropertiesProvider(String fileLocation, String keyStorePath , String keyStorePass , String keyPass, String keyAlias, ResourceProvider resourceProvider) {
		super(fileLocation, resourceProvider);
		this.file=fileLocation;
		this.keystorePath = keyStorePath;
		this.keystorePass = keyStorePass;
		this.keyPass = keyPass;
		this.keyAlias = keyAlias;
	}	
	
		
	@Override
    public Optional<ConfigurationProperty> getConfigurationProperty(String configurationAttributeKey) {
		
		
      // TODO change implementation to discover properties values from your custom source
      if (configurationAttributeKey.startsWith(RSA_ENC_PREFIX)) {
        String effectiveKey = configurationAttributeKey.substring(RSA_ENC_PREFIX.length());
        ConfigurationProperty originalConfigurationProperty = super.configurationAttributes.get(effectiveKey);
        if (originalConfigurationProperty == null) {
          return Optional.empty();
        }
        String originalString = ((String) originalConfigurationProperty.getRawValue());
        
        //First get private public keypair
        try {
        		KeyPair kp = RsaUtility.getKeyPairFromKeyStore(this.keystorePath, this.keystorePass , this.keyPass ,this.keyAlias , resourceProvider);
            decryptedValue = RsaUtility.decrypt(originalString, kp.getPrivate());
        }catch(Exception ex) {
        		ex.printStackTrace();
        }
        
        return Optional.of(new ConfigurationProperty() {

          @Override
          public Object getSource() {
            return "RSA Encryption utility";
          }

          @Override
          public Object getRawValue() {
        	  	
            return decryptedValue;
          }

          @Override
          public String getKey() {
            return effectiveKey;
          }
        });
      
      }
      return Optional.empty();
    }

	public String getFile() {
		return file;
	}

	public void setFile(String file) {
		this.file = file;
	}

	public String getKeystorePath() {
		return keystorePath;
	}

	public void setKeystorePath(String keystorePath) {
		this.keystorePath = keystorePath;
	}

	public String getKeystorePass() {
		return keystorePass;
	}

	public void setKeystorePass(String keystorePass) {
		this.keystorePass = keystorePass;
	}

	public String getKeyPass() {
		return keyPass;
	}

	public void setKeyPass(String keyPass) {
		this.keyPass = keyPass;
	}
	
}
