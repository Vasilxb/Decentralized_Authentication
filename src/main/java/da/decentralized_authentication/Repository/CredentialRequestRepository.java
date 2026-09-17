package da.decentralized_authentication.Repository;

import da.decentralized_authentication.Model.CredentialRequest;
import da.decentralized_authentication.Model.Enum.CredentialRequestStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CredentialRequestRepository extends JpaRepository<CredentialRequest, Long> {
    List<CredentialRequest> findByHolderId(Long holderId);
    List<CredentialRequest> findByStatus(CredentialRequestStatus status);
}
