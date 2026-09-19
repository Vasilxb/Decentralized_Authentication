package da.decentralized_authentication.Service;

import da.decentralized_authentication.Model.VerificationCode;
import da.decentralized_authentication.Model.Enum.VerificationResult;
import da.decentralized_authentication.Model.Enum.VerificationType;

import java.time.LocalDate;

public interface VerificationCodeService {
    void generateRegisterCode(
            String email,
            String pendingUsername,
            String pendingFullName,
            LocalDate pendingDateOfBirth,
            String pendingAddress,
            String pendingPasswordHash,
            String pendingPasswordSalt
    );
    void generateLoginCode(String username, String email);
    VerificationOutcome verify(String identifier, VerificationType type, String inputCode);

    record VerificationOutcome(VerificationResult result, VerificationCode code) {}
}