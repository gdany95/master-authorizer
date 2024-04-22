package ro.linic.cloud.master.authorizer.component;

import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import ro.linic.cloud.master.authorizer.repository.InviteTokenRepository;

@Component
public class JobScheduler {
	@Autowired private InviteTokenRepository tokenRepo;
	
	@Scheduled(cron = "${cron.check-expired-tokens:0 0 * * * *}") // every hour
    public void removeExpiredInviteTokens() {
		tokenRepo.findAllByExpiryDateBefore(Instant.now()).forEach(tokenRepo::delete);
    }
}
