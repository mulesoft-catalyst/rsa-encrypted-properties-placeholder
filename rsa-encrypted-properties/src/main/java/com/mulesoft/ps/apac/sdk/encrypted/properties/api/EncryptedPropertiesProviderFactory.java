package com.mulesoft.ps.apac.sdk.encrypted.properties.api;


import static org.mule.runtime.api.component.ComponentIdentifier.builder;
import org.mule.runtime.api.component.ComponentIdentifier;
import org.mule.runtime.config.api.dsl.model.ConfigurationParameters;
import org.mule.runtime.config.api.dsl.model.ResourceProvider;
import org.mule.runtime.config.api.dsl.model.properties.ConfigurationPropertiesProvider;
import org.mule.runtime.config.api.dsl.model.properties.ConfigurationPropertiesProviderFactory;

public class EncryptedPropertiesProviderFactory implements ConfigurationPropertiesProviderFactory {
	
	public static final String EXTENSION_NAMESPACE = "rsa-encryption-utility";
	  public static final String RSA_ENC_CONFIGURATION_PROPERTIES_ELEMENT = "config";
	  public static final ComponentIdentifier RSA_ENC_CONFIGURATION_PROPERTIES =
	      builder().namespace(EXTENSION_NAMESPACE).name(RSA_ENC_CONFIGURATION_PROPERTIES_ELEMENT).build();

	
	
	@Override
	public ComponentIdentifier getSupportedComponentIdentifier() {
		return RSA_ENC_CONFIGURATION_PROPERTIES;
	}

	@Override
	public ConfigurationPropertiesProvider createProvider(ConfigurationParameters parameters,
			ResourceProvider externalResourceProvider) {
		// This is how you can access the configuration parameter of the <custom-properties-provider:config> element.
	    String file = parameters.getStringParameter("file");
	    String keystorepath= parameters.getStringParameter("keystorepath");
	    String keystorepass= parameters.getStringParameter("keystorepass");
	    String keypass= parameters.getStringParameter("keypass");
	    String keyAlias= parameters.getStringParameter("keyAlias");

		return new EncryptedPropertiesProvider(file,keystorepath, keystorepass , keypass ,keyAlias , externalResourceProvider);
	}

}
