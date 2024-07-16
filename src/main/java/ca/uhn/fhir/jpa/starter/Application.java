package ca.uhn.fhir.jpa.starter;

import ca.uhn.fhir.batch2.jobs.config.Batch2JobsConfig;
import ca.uhn.fhir.jpa.batch2.JpaBatch2Config;
import ca.uhn.fhir.jpa.starter.annotations.OnEitherVersion;
import ca.uhn.fhir.jpa.starter.cdshooks.StarterCdsHooksConfig;
import ca.uhn.fhir.jpa.starter.common.FhirTesterConfig;
import ca.uhn.fhir.jpa.starter.cr.StarterCrDstu3Config;
import ca.uhn.fhir.jpa.starter.cr.StarterCrR4Config;
import ca.uhn.fhir.jpa.starter.mdm.MdmConfig;
import ca.uhn.fhir.jpa.subscription.channel.config.SubscriptionChannelConfig;
import ca.uhn.fhir.jpa.subscription.match.config.SubscriptionProcessorConfig;
import ca.uhn.fhir.jpa.subscription.match.config.WebsocketDispatcherConfig;
import ca.uhn.fhir.jpa.subscription.submit.config.SubscriptionSubmitterConfig;
import ca.uhn.fhir.rest.server.RestfulServer;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.elasticsearch.ElasticsearchRestClientAutoConfiguration;
import org.springframework.boot.autoconfigure.thymeleaf.ThymeleafAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Import;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;

// import com.lantanagroup.pdex.CapabilityStatementCustomizer;
import com.lantanagroup.pdex.security.AuthInterceptor;
import com.lantanagroup.pdex.security.SearchInterceptor;
import com.lantanagroup.pdex.security.SecurityProperties;
import com.lantanagroup.pdex.security.SmartDiscoveryInterceptor;

import com.avaneerhealth.pdex.KeycloakInterceptor;
import com.avaneerhealth.pdex.KeycloakProperties;
import com.avaneerhealth.pdex.CapabilityStatementCustomizer;

@ComponentScan(basePackages = {"ca.uhn.fhir.jpa.starter", "com.lantanagroup.pdex"})
@ServletComponentScan(basePackageClasses = {RestfulServer.class})
@SpringBootApplication(exclude = {ElasticsearchRestClientAutoConfiguration.class, ThymeleafAutoConfiguration.class})
@Import({
	StarterCrR4Config.class,
	StarterCrDstu3Config.class,
	StarterCdsHooksConfig.class,
	SubscriptionSubmitterConfig.class,
	SubscriptionProcessorConfig.class,
	SubscriptionChannelConfig.class,
	WebsocketDispatcherConfig.class,
	MdmConfig.class,
	JpaBatch2Config.class,
	Batch2JobsConfig.class
})
public class Application extends SpringBootServletInitializer {

  public static void main(String[] args) {

    SpringApplication.run(Application.class, args);

    //Server is now accessible at eg. http://localhost:8080/fhir/metadata
    //UI is now accessible at http://localhost:8080/
  }

  @Override
  protected SpringApplicationBuilder configure(
    SpringApplicationBuilder builder) {
    return builder.sources(Application.class);
  }

  @Autowired
  AutowireCapableBeanFactory beanFactory;

  @Autowired
  AppProperties appProperties;
  @Autowired
  SecurityProperties securityProperties;

  // skehlet
  @Autowired
  KeycloakProperties keycloakProperties;

  @Bean
  @Conditional(OnEitherVersion.class)
  public ServletRegistrationBean hapiServletRegistration(RestfulServer restfulServer) {

    // Register capability statement customizer
    // restfulServer.registerInterceptor(new CapabilityStatementCustomizer(appProperties, securityProperties));
    // skehlet: use mine for now
    restfulServer.registerInterceptor(new CapabilityStatementCustomizer(keycloakProperties));

    // Add interceptors for SMART on FHIR support
    restfulServer.registerInterceptor(new SmartDiscoveryInterceptor(appProperties, securityProperties));
    // restfulServer.registerInterceptor(new AuthInterceptor(appProperties, securityProperties));
    // skehlet: use mine for now
    restfulServer.registerInterceptor(new KeycloakInterceptor(keycloakProperties));
    restfulServer.registerInterceptor(new SearchInterceptor(appProperties, securityProperties));

    ServletRegistrationBean servletRegistrationBean = new ServletRegistrationBean();
    /* Removed by Corey Spears, Added registerProvider to StarterJpaConfig instead
    // Added by Rick Geimer to wire custom operations
    List<IResourceProvider> resourceProviders = new ArrayList<IResourceProvider>();
    List<IResourceProvider> old = restfulServer.getResourceProviders();
    resourceProviders.addAll(old);
    resourceProviders.add(new MemberMatchProvider());
    restfulServer.setResourceProviders(resourceProviders);
    // End Rick stuff
     */
    beanFactory.autowireBean(restfulServer);
    servletRegistrationBean.setServlet(restfulServer);
    servletRegistrationBean.addUrlMappings("/fhir/*");
    servletRegistrationBean.setLoadOnStartup(1);

    return servletRegistrationBean;
  }

  // @Bean
  // public ServletRegistrationBean overlayRegistrationBean() {

  //   AnnotationConfigWebApplicationContext annotationConfigWebApplicationContext = new AnnotationConfigWebApplicationContext();
  //   annotationConfigWebApplicationContext.register(FhirTesterConfig.class);

  //   DispatcherServlet dispatcherServlet = new DispatcherServlet(
  //     annotationConfigWebApplicationContext);
  //   dispatcherServlet.setContextClass(AnnotationConfigWebApplicationContext.class);
  //   dispatcherServlet.setContextConfigLocation(FhirTesterConfig.class.getName());

  //   ServletRegistrationBean registrationBean = new ServletRegistrationBean();
  //   registrationBean.setServlet(dispatcherServlet);
  //   registrationBean.addUrlMappings("/*");
  //   registrationBean.setLoadOnStartup(1);
  //   return registrationBean;

  // }
}
