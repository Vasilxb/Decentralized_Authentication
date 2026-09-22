package da.decentralized_authentication.Service.ServiceImpl;

import da.decentralized_authentication.Model.Enum.AccountStatus;
import da.decentralized_authentication.Model.Enum.UserRole;
import da.decentralized_authentication.Model.Enum.VerificationResult;
import da.decentralized_authentication.Model.Enum.VerificationType;
import da.decentralized_authentication.Model.User;
import da.decentralized_authentication.Model.VerificationCode;
import da.decentralized_authentication.Repository.UserRepository;
import da.decentralized_authentication.Service.AuthService;
import da.decentralized_authentication.Service.SessionService;
import da.decentralized_authentication.Service.VerificationCodeService;
import da.decentralized_authentication.Util.IdPhotoStorageService;
import da.decentralized_authentication.Util.PasswordUtil;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;
import java.util.*;

@Service
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordUtil passwordUtil;
    private final VerificationCodeService verificationCodeService;
    private final SessionService sessionService;
    private final IdPhotoStorageService photoStorageService;
    @Value("${app.security.no-2fa-usernames:}")
    private String noTwoFaUsernamesRaw;


    public AuthServiceImpl(UserRepository userRepository,
                           PasswordUtil passwordUtil,
                           VerificationCodeService verificationCodeService,
                           SessionService sessionService, IdPhotoStorageService photoStorageService) {
        this.userRepository = userRepository;
        this.passwordUtil = passwordUtil;
        this.verificationCodeService = verificationCodeService;
        this.sessionService = sessionService;
        this.photoStorageService = photoStorageService;
    }

    @PostConstruct
    public void initializeDefaultAdmin() {
        if (userRepository.existsByUsername("admin")) return;
        String salt = passwordUtil.generateSalt();
        String hash = passwordUtil.hash("admin123", salt);
        User admin = new User("admin", "Default Admin", LocalDate.of(1990, 1, 1),
                "N/A", "твојата-реална-адреса@gmail.com", hash, salt);
        admin.setRole(UserRole.ADMIN);
        admin.setAccountStatus(AccountStatus.ACTIVE); // НОВО - admin прескокнува ID photo
        userRepository.save(admin);
        System.out.println("Default admin created: username=admin, password=admin123");
    }

    @Override
    public boolean startRegistration(
            String username,
            String fullName,
            LocalDate dob,
            String address,
            String email,
            String password
    ) {
        if (userRepository.existsByUsername(username)
                || userRepository.existsByEmail(email)) {
            return false;
        }
        String passwordSalt = passwordUtil.generateSalt();
        String passwordHash = passwordUtil.hash(
                password,
                passwordSalt
        );
        verificationCodeService.generateRegisterCode(
                email,
                username,
                fullName,
                dob,
                address,
                passwordHash,
                passwordSalt
        );
        return true;
    }

    @Override
    @Transactional
    public VerificationResult completeRegistration(
            String email,
            String code
    ) {
        VerificationCodeService.VerificationOutcome outcome =
                verificationCodeService.verify(
                        email,
                        VerificationType.REGISTER,
                        code
                );
        if (outcome.result() != VerificationResult.SUCCESS) {
            return outcome.result();
        }
        VerificationCode verificationCode = outcome.code();
        if (verificationCode == null) {
            return VerificationResult.NOT_FOUND;
        }
        if (userRepository.existsByUsername(
                verificationCode.getPendingUsername()
        )) {
            return VerificationResult.USERNAME_TAKEN;
        }
        if (userRepository.existsByEmail(email)) {
            return VerificationResult.EMAIL_TAKEN;
        }
        User user = new User(
                verificationCode.getPendingUsername(),
                verificationCode.getPendingFullName(),
                verificationCode.getPendingDateOfBirth(),
                verificationCode.getPendingAddress(),
                email,
                verificationCode.getPendingPasswordHash(),
                verificationCode.getPendingPasswordSalt()
        );
        userRepository.save(user);
        return VerificationResult.SUCCESS;
    }

    @Override
    public boolean checkPassword(String username, String password) {
        return userRepository.findByUsername(username)
                .filter(User::isEnabled)
                .map(user -> passwordUtil.matches(
                        password,
                        user.getSalt(),
                        user.getPasswordHash()
                ))
                .orElse(false);
    }

    @Override
    public boolean requiresTwoFactor(String username) {
        Set<String> exempt = new HashSet<>(Arrays.asList(noTwoFaUsernamesRaw.split(",")));
        return !exempt.contains(username.trim());
    }

    @Override
    public void requestLoginCode(String username) {
        userRepository.findByUsername(username)
                .filter(User::isEnabled)
                .ifPresent(user ->
                        verificationCodeService.generateLoginCode(
                                username,
                                user.getEmail()
                        )
                );
    }

    @Override
    public String directLogin(String username) {
        return userRepository.findByUsername(username)
                .filter(User::isEnabled)
                .map(user -> sessionService.createSession(user.getId()))
                .orElse(null);
    }

    @Override
    public String completeLogin(String username, String code) {
        VerificationCodeService.VerificationOutcome outcome =
                verificationCodeService.verify(
                        username,
                        VerificationType.LOGIN,
                        code
                );
        if (outcome.result() == VerificationResult.SUCCESS) {
            return userRepository.findByUsername(username)
                    .filter(User::isEnabled)
                    .map(user -> sessionService.createSession(user.getId()))
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
    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email);
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
    @Override
    public void uploadIdPhoto(Long userId, MultipartFile file) throws Exception {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Корисникот не постои"));

        String path = photoStorageService.store(file);
        user.setIdPhotoPath(path);
        user.setAccountStatus(AccountStatus.PENDING_REVIEW);
        userRepository.save(user);
    }

    @Override
    public void approveIdPhoto(Long userId) {
        userRepository.findById(userId).ifPresent(u -> {
            u.setAccountStatus(AccountStatus.ACTIVE);
            userRepository.save(u);
        });
    }

    @Override
    public void rejectIdPhoto(Long userId, String reason) {
        userRepository.findById(userId).ifPresent(u -> {
            u.setIdPhotoRejectionCount(u.getIdPhotoRejectionCount() + 1);
            u.setLastRejectionReason(reason);
            if (u.getIdPhotoRejectionCount() >= 3) {
                u.setAccountStatus(AccountStatus.REJECTED);
            } else {
                u.setAccountStatus(AccountStatus.PENDING_PHOTO); // дозволи повторен обид
            }
            userRepository.save(u);
        });
    }

    @Override
    public List<User> getPendingReviewUsers() {
        return userRepository.findAll().stream()
                .filter(u -> u.getAccountStatus() == AccountStatus.PENDING_REVIEW)
                .toList();
    }
}