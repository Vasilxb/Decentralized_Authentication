package da.decentralized_authentication.Service.ServiceImpl;

import da.decentralized_authentication.Model.Enum.VerificationResult;
import da.decentralized_authentication.Model.Enum.VerificationType;
import da.decentralized_authentication.Model.VerificationCode;
import da.decentralized_authentication.Repository.VerificationCodeRepository;
import da.decentralized_authentication.Service.EmailService;
import da.decentralized_authentication.Service.VerificationCodeService;
import da.decentralized_authentication.Util.PasswordUtil;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class VerificationCodeServiceImpl implements VerificationCodeService {

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
    @Transactional
    public void generateRegisterCode(
            String email,
            String pendingUsername,
            String pendingFullName,
            LocalDate pendingDateOfBirth,
            String pendingAddress,
            String pendingPasswordHash,
            String pendingPasswordSalt
    ) {
        codeRepository
                .findTopByIdentifierAndTypeAndUsedFalseOrderByIdDesc(
                        email,
                        VerificationType.REGISTER
                )
                .ifPresent(codeRepository::delete);
        String plainCode = generatePlainCode();
        String codeSalt = passwordUtil.generateSalt();
        String codeHash = passwordUtil.hash(plainCode, codeSalt);
        VerificationCode verificationCode = new VerificationCode(
                email,
                codeHash,
                codeSalt,
                VerificationType.REGISTER,
                LocalDateTime.now().plusMinutes(EXPIRY_MINUTES)
        );
        verificationCode.setPendingUsername(pendingUsername);
        verificationCode.setPendingFullName(pendingFullName);
        verificationCode.setPendingDateOfBirth(pendingDateOfBirth);
        verificationCode.setPendingAddress(pendingAddress);
        verificationCode.setPendingPasswordHash(pendingPasswordHash);
        verificationCode.setPendingPasswordSalt(pendingPasswordSalt);
        codeRepository.save(verificationCode);
        emailService.sendVerificationCode(email, plainCode);
    }

    @Override
    @Transactional
    public void generateLoginCode(String username, String email) {
        codeRepository.findTopByIdentifierAndTypeAndUsedFalseOrderByIdDesc(username, VerificationType.LOGIN)
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
    @Transactional
    public VerificationOutcome verify(
            String identifier,
            VerificationType type,
            String inputCode
    ) {
        if (inputCode == null || !inputCode.matches("\\d{6}")) {
            return new VerificationOutcome(
                    VerificationResult.WRONG_CODE,
                    null
            );
        }
        Optional<VerificationCode> optionalCode =
                codeRepository
                        .findTopByIdentifierAndTypeAndUsedFalseOrderByIdDesc(
                                identifier,
                                type
                        );
        if (optionalCode.isEmpty()) {
            return new VerificationOutcome(
                    VerificationResult.NOT_FOUND,
                    null
            );
        }
        VerificationCode verificationCode = optionalCode.get();

        if (verificationCode.getExpiresAt() == null
                || LocalDateTime.now()
                .isAfter(verificationCode.getExpiresAt())) {
            verificationCode.setUsed(true);
            codeRepository.save(verificationCode);
            return new VerificationOutcome(
                    VerificationResult.EXPIRED,
                    verificationCode
            );
        }

        boolean codeMatches = passwordUtil.matches(
                inputCode,
                verificationCode.getSalt(),
                verificationCode.getCodeHash()
        );
        if (codeMatches) {
            verificationCode.setUsed(true);
            codeRepository.save(verificationCode);
            return new VerificationOutcome(
                    VerificationResult.SUCCESS,
                    verificationCode
            );
        }
        int attempts = verificationCode.getAttemptCount() + 1;
        verificationCode.setAttemptCount(attempts);
        if (attempts >= MAX_ATTEMPTS) {
            verificationCode.setUsed(true);
            codeRepository.save(verificationCode);
            return new VerificationOutcome(
                    VerificationResult.LOCKED,
                    verificationCode
            );
        }
        codeRepository.save(verificationCode);
        return new VerificationOutcome(
                VerificationResult.WRONG_CODE,
                verificationCode
        );
    }

    private String generatePlainCode() {
        return String.format("%06d", new SecureRandom().nextInt(1_000_000));
    }
}