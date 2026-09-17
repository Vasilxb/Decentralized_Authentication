package da.decentralized_authentication.Service;

import java.util.Optional;

public interface SessionService {
    String createSession(Long userId);
    Optional<Long> validate(String token);
    void invalidate(String token);
}