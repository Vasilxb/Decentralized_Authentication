package da.decentralized_authentication.Repository;

import da.decentralized_authentication.Model.VerifierRequest;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface VerifierRequestRepository extends JpaRepository<VerifierRequest, Long> {
    List<VerifierRequest> findByHolderId(Long holderId);
}
