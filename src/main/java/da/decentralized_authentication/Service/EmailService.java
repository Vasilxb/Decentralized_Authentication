package da.decentralized_authentication.Service;

public interface EmailService {
    void sendVerificationCode(String recipient, String code);
}