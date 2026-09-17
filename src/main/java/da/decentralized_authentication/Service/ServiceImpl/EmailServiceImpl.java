package da.decentralized_authentication.Service.ServiceImpl;

import da.decentralized_authentication.Service.EmailService;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {
    @Override
    public void sendVerificationCode(String toEmail, String code) {
        System.out.println("[EMAIL] До: " + toEmail + " | Верификациски код: " + code);
    }
}
