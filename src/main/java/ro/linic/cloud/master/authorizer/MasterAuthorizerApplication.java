package ro.linic.cloud.master.authorizer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class MasterAuthorizerApplication {

	public static void main(final String[] args) {
		SpringApplication.run(MasterAuthorizerApplication.class, args);
	}

}
