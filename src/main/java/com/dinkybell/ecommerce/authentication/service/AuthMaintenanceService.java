package com.dinkybell.ecommerce.authentication.service;

import java.time.LocalDateTime;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;

/**
 * Service responsible for authentication maintenance tasks.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthMaintenanceService {

    private final UserAuthenticationRepository authenticationRepository;

    /**
     * Scheduled task that removes expired user data not confirmed by e-mail after 48 hours.
     * Runs automatically every day at midnight to keep the database clean.
     */
    @Scheduled(cron = "0 0 0 * * *") // Every day at midnight
    @Transactional
    public void cleanupExpiredUsers() {
        LocalDateTime threshold = LocalDateTime.now().minusHours(48);
        log.info("Running scheduled cleanup of expired unconfirmed users before {}", threshold);
        int deletedCount = authenticationRepository.deleteExpiredUsers(threshold);
        if (deletedCount > 0) {
            log.info("Removed {} expired users from the database", deletedCount);
        }
    }
}
