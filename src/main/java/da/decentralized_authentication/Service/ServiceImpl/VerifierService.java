package da.decentralized_authentication.Service.ServiceImpl;

import da.decentralized_authentication.Model.Enum.VerifierRequestStatus;
import da.decentralized_authentication.Model.VerifierRequest;
import da.decentralized_authentication.Repository.VerifierRequestRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class VerifierService implements da.decentralized_authentication.Service.VerifierService {

    private final VerifierRequestRepository requestRepository;

    public VerifierService(VerifierRequestRepository requestRepository) {
        this.requestRepository = requestRepository;
    }

    @Override
    public VerifierRequest submitRequest(Long holderId, String verifierName, String credentialType) {
        return requestRepository.save(new VerifierRequest(holderId, verifierName, credentialType));
    }

    @Override
    public List<VerifierRequest> getRequestsForHolder(Long holderId) {
        return requestRepository.findByHolderId(holderId);
    }

    @Override
    public void approve(Long requestId, Long credentialId) {
        requestRepository.findById(requestId).ifPresent(r -> {
            r.setStatus(VerifierRequestStatus.APPROVED);
            r.setCredentialId(credentialId);  // ново поле - најди во VerifierRequest.java
            r.setRespondedAt(LocalDateTime.now());
            requestRepository.save(r);
        });
    }

    @Override
    public void deny(Long requestId) {
        requestRepository.findById(requestId).ifPresent(r -> {
            r.setStatus(VerifierRequestStatus.DENIED);
            r.setRespondedAt(LocalDateTime.now());
            requestRepository.save(r);
        });
    }
}