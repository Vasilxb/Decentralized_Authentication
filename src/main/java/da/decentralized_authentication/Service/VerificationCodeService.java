package da.decentralized_authentication.Service;

import da.decentralized_authentication.Model.VerificationCode;
import da.decentralized_authentication.Model.Enum.VerificationResult;
import da.decentralized_authentication.Model.Enum.VerificationType;

public interface VerificationCodeService {
    void generateRegisterCode(String email, String pendingUsername,
                              String pendingPasswordHash, String pendingPasswordSalt);
    void generateLoginCode(String username, String email);
    VerificationOutcome verify(String identifier, VerificationType type, String inputCode);

    record VerificationOutcome(VerificationResult result, VerificationCode code) {}
}