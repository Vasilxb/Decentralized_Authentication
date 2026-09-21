package da.decentralized_authentication.Service;

import da.decentralized_authentication.Model.VerifierRequest;

import java.util.List;
import java.util.Optional;

public interface VerifierService {
    VerifierRequest submitRequest(Long holderId, String verifierName, String credentialType);
    List<VerifierRequest> getRequestsForHolder(Long holderId);
    Optional<VerifierRequest> getRequestById(Long requestId);
    void approve(Long requestId, Long credentialId); // ажурирано - сега бара и credentialId
    void deny(Long requestId);
}
