package da.decentralized_authentication.Service.ServiceImpl;

import da.decentralized_authentication.Model.Enum.VerificationResult;
import da.decentralized_authentication.Model.Enum.VerificationType;
import da.decentralized_authentication.Service.EmailService;
import da.decentralized_authentication.Model.*;
import da.decentralized_authentication.Repository.VerificationCodeRepository;
import da.decentralized_authentication.Util.PasswordUtil;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class VerificationCodeServiceImpl implements da.decentralized_authentication.Service.VerificationCodeService {

    private static final int EXPIRY_MINUTES = 10;
    private static final int MAX_ATTEMPTS = 3;

    private final VerificationCodeRepository codeRepository;
    private final PasswordUtil passwordUtil;
    private final EmailService emailService;

    public VerificationCodeServiceImpl(VerificationCodeRepository codeRepository,
                                       PasswordUtil passwordUtil,
                                       EmailService emailService) {
        this.codeRepository = codeRepository;
        this.passwordUtil = passwordUtil;
        this.emailService = emailService;
    }

    @Override
    public void generateRegisterCode(String email, String pendingUsername,
                                     String pendingPasswordHash, String pendingPasswordSalt) {
        codeRepository.findTopByIdentifierAndTypeOrderByIdDesc(email, VerificationType.REGISTER)
                .ifPresent(codeRepository::delete);

        String plainCode = generatePlainCode();
        String codeSalt = passwordUtil.generateSalt();
        String codeHash = passwordUtil.hash(plainCode, codeSalt);

        VerificationCode vc = new VerificationCode(email, codeHash, codeSalt,
                VerificationType.REGISTER, LocalDateTime.now().plusMinutes(EXPIRY_MINUTES));
        vc.setPendingUsername(pendingUsername);
        vc.setPendingPasswordHash(pendingPasswordHash);
        vc.setPendingPasswordSalt(pendingPasswordSalt);

        codeRepository.save(vc);
        emailService.sendVerificationCode(email, plainCode);
    }

    @Override
    public void generateLoginCode(String username, String email) {
        codeRepository.findTopByIdentifierAndTypeOrderByIdDesc(username, VerificationType.LOGIN)
                .ifPresent(codeRepository::delete);

        String plainCode = generatePlainCode();
        String codeSalt = passwordUtil.generateSalt();
        String codeHash = passwordUtil.hash(plainCode, codeSalt);

        VerificationCode vc = new VerificationCode(username, codeHash, codeSalt,
                VerificationType.LOGIN, LocalDateTime.now().plusMinutes(EXPIRY_MINUTES));

        codeRepository.save(vc);
        emailService.sendVerificationCode(email, plainCode);
    }

    @Override
    public VerificationOutcome verify(String identifier, VerificationType type, String inputCode) {
        Optional<VerificationCode> opt =
                codeRepository.findTopByIdentifierAndTypeAndUsedFalseOrderByIdDesc(identifier, type);

        if (opt.isEmpty()) return new VerificationOutcome(VerificationResult.NOT_FOUND, null);
        VerificationCode vc = opt.get();

        if (LocalDateTime.now().isAfter(vc.getExpiresAt())) {
            return new VerificationOutcome(VerificationResult.EXPIRED, vc);
        }
        if (vc.getAttemptCount() >= MAX_ATTEMPTS) {
            return new VerificationOutcome(VerificationResult.LOCKED, vc);
        }

        if (passwordUtil.matches(inputCode, vc.getSalt(), vc.getCodeHash())) {
            vc.setUsed(true);
            codeRepository.save(vc);
            return new VerificationOutcome(VerificationResult.SUCCESS, vc);
        } else {
            vc.setAttemptCount(vc.getAttemptCount() + 1);
            codeRepository.save(vc);
            var result = vc.getAttemptCount() >= MAX_ATTEMPTS
                    ? VerificationResult.LOCKED : VerificationResult.WRONG_CODE;
            return new VerificationOutcome(result, vc);
        }
    }

    private String generatePlainCode() {
        return String.format("%06d", new SecureRandom().nextInt(999999));
    }
}