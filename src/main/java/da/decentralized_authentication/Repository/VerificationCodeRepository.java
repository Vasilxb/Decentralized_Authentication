package da.decentralized_authentication.Repository;

import da.decentralized_authentication.Model.Enum.VerificationType;
import da.decentralized_authentication.Model.VerificationCode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.Optional;

public interface VerificationCodeRepository extends JpaRepository<VerificationCode, Long> {
    Optional<VerificationCode> findTopByIdentifierAndTypeAndUsedFalseOrderByIdDesc(
            String identifier, VerificationType type);
    Optional<VerificationCode> findTopByIdentifierAndTypeOrderByIdDesc(
            String identifier, VerificationType type);
}