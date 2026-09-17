package da.decentralized_authentication.Service;

import da.decentralized_authentication.Model.Credential;
import da.decentralized_authentication.Model.CredentialRequest;

import java.util.List;

public interface CredentialService {
    CredentialRequest requestCredential(Long holderId, String type, String proofDocumentPath);
    List<CredentialRequest> getPendingRequests();
    List<CredentialRequest> getRequestsForHolder(Long holderId);
    void approveRequest(Long requestId, Long adminId) throws Exception;
    void denyRequest(Long requestId, Long adminId);
    List<Credential> getCredentialsForHolder(Long holderId);
    void revokeCredential(Long credentialId, String reason);
    void revokeAllForHolder(Long holderId, String reason); // НОВО
    void deleteCredential(Long credentialId);
    boolean verifyCredential(Long credentialId) throws Exception;
}