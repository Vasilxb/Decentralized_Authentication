package da.decentralized_authentication.Service.ServiceImpl;

import da.decentralized_authentication.Model.Session;
import da.decentralized_authentication.Repository.SessionRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class SessionService implements da.decentralized_authentication.Service.SessionService {

    private static final int SESSION_HOURS = 4;
    private final SessionRepository sessionRepository;

    public SessionService(SessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    @Override
    public String createSession(Long userId) {
        String token = UUID.randomUUID().toString();
        sessionRepository.save(new Session(token, userId, LocalDateTime.now().plusHours(SESSION_HOURS)));
        return token;
    }

    @Override
    public Optional<Long> validate(String token) {
        return sessionRepository.findById(token)
                .filter(s -> LocalDateTime.now().isBefore(s.getExpiresAt()))
                .map(Session::getUserId);
    }

    @Override
    public void invalidate(String token) {
        sessionRepository.findById(token).ifPresent(sessionRepository::delete);
    }
}