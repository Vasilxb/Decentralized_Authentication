package da.decentralized_authentication.Service.ServiceImpl;

import da.decentralized_authentication.Model.Enum.UserRole;
import da.decentralized_authentication.Model.Enum.VerificationResult;
import da.decentralized_authentication.Model.Enum.VerificationType;
import da.decentralized_authentication.Service.SessionService;
import da.decentralized_authentication.Service.VerificationCodeService;
import da.decentralized_authentication.Model.*;
import da.decentralized_authentication.Repository.UserRepository;
import da.decentralized_authentication.Repository.VerificationCodeRepository;
import da.decentralized_authentication.Util.PasswordUtil;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class AuthService implements da.decentralized_authentication.Service.AuthService {

    private static final int EXPIRY_MINUTES = 10;

    private final UserRepository userRepository;
    private final VerificationCodeRepository codeRepository;
    private final PasswordUtil passwordUtil;
    private final VerificationCodeService verificationCodeService;
    private final SessionService sessionService;

    public AuthService(UserRepository userRepository, VerificationCodeRepository codeRepository,
                       PasswordUtil passwordUtil, VerificationCodeService verificationCodeService,
                       SessionService sessionService) {
        this.userRepository = userRepository;
        this.codeRepository = codeRepository;
        this.passwordUtil = passwordUtil;
        this.verificationCodeService = verificationCodeService;
        this.sessionService = sessionService;
    }

    @PostConstruct
    public void initializeDefaultAdmin() {
        if (userRepository.existsByUsername("admin")) return;
        String salt = passwordUtil.generateSalt();
        String hash = passwordUtil.hash("admin123", salt);
        User admin = new User("admin", "Default Admin", LocalDate.of(1990, 1, 1),
                "N/A", "admin@example.com", hash, salt);
        admin.setRole(UserRole.ADMIN);
        userRepository.save(admin);
        System.out.println("Default admin created: username=admin, password=admin123");
    }

    @Override
    public boolean startRegistration(String username, String fullName, LocalDate dob,
                                     String address, String email, String password) {
        if (userRepository.existsByUsername(username) || userRepository.existsByEmail(email)) {
            return false;
        }
        String salt = passwordUtil.generateSalt();
        String hash = passwordUtil.hash(password, salt);

        codeRepository.findTopByIdentifierAndTypeAndUsedFalseOrderByIdDesc(email, VerificationType.REGISTER)
                .ifPresent(codeRepository::delete);

        String plainCode = String.format("%06d", new java.security.SecureRandom().nextInt(999999));
        String codeSalt = passwordUtil.generateSalt();
        String codeHash = passwordUtil.hash(plainCode, codeSalt);

        VerificationCode vc = new VerificationCode(email, codeHash, codeSalt,
                VerificationType.REGISTER, LocalDateTime.now().plusMinutes(EXPIRY_MINUTES));
        vc.setPendingUsername(username);
        vc.setPendingFullName(fullName);
        vc.setPendingDateOfBirth(dob);
        vc.setPendingAddress(address);
        vc.setPendingPasswordHash(hash);
        vc.setPendingPasswordSalt(salt);
        codeRepository.save(vc);

        System.out.println("[EMAIL] До: " + email + " | Верификациски код: " + plainCode);
        return true;
    }

    @Override
    public VerificationResult completeRegistration(String email, String code) {
        var outcome = verificationCodeService.verify(email, VerificationType.REGISTER, code);
        if (outcome.result() == VerificationResult.SUCCESS) {
            var vc = outcome.code();
            User user = new User(vc.getPendingUsername(), vc.getPendingFullName(),
                    vc.getPendingDateOfBirth(), vc.getPendingAddress(), email,
                    vc.getPendingPasswordHash(), vc.getPendingPasswordSalt());
            userRepository.save(user);
        }
        return outcome.result();
    }

    @Override
    public boolean checkPassword(String username, String password) {
        return userRepository.findByUsername(username)
                .filter(User::isEnabled)
                .map(u -> passwordUtil.matches(password, u.getSalt(), u.getPasswordHash()))
                .orElse(false);
    }

    @Override
    public void requestLoginCode(String username) {
        userRepository.findByUsername(username)
                .ifPresent(u -> verificationCodeService.generateLoginCode(username, u.getEmail()));
    }

    @Override
    public String completeLogin(String username, String code) {
        var outcome = verificationCodeService.verify(username, VerificationType.LOGIN, code);
        if (outcome.result() == VerificationResult.SUCCESS) {
            return userRepository.findByUsername(username)
                    .map(u -> sessionService.createSession(u.getId()))
                    .orElse(null);
        }
        if (outcome.result() == VerificationResult.LOCKED) {
            revokeUser(username);
        }
        return null;
    }

    @Override
    public void revokeUser(String username) {
        userRepository.findByUsername(username).ifPresent(u -> {
            u.setEnabled(false);
            userRepository.save(u);
        });
    }

    @Override
    public Optional<User> getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public void updateUser(User user) {
        userRepository.save(user);
    }

    @Override
    public void enableUser(String username) {
        userRepository.findByUsername(username).ifPresent(u -> {
            u.setEnabled(true);
            userRepository.save(u);
        });
    }
}