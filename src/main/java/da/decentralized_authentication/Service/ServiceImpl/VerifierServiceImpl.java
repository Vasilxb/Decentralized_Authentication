package da.decentralized_authentication.Service.ServiceImpl;

import da.decentralized_authentication.Model.Enum.VerifierRequestStatus;
import da.decentralized_authentication.Model.VerifierRequest;
import da.decentralized_authentication.Repository.VerifierRequestRepository;
import da.decentralized_authentication.Service.VerifierService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class VerifierServiceImpl implements VerifierService {

    private final VerifierRequestRepository requestRepository;

    public VerifierServiceImpl(VerifierRequestRepository requestRepository) {
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
    public Optional<VerifierRequest> getRequestById(Long requestId) {
        return requestRepository.findById(requestId);
    }

    @Override
    public void approve(Long requestId, Long credentialId) {
        requestRepository.findById(requestId).ifPresent(r -> {
            if (r.getStatus() != VerifierRequestStatus.PENDING) {
                return;
            }
            r.setStatus(VerifierRequestStatus.APPROVED);
            r.setCredentialId(credentialId);
            r.setRespondedAt(LocalDateTime.now());
            requestRepository.save(r);
        });
    }

    @Override
    public void deny(Long requestId) {
        requestRepository.findById(requestId).ifPresent(r -> {
            if (r.getStatus() != VerifierRequestStatus.PENDING) {
                return;
            }
            r.setStatus(VerifierRequestStatus.DENIED);
            r.setRespondedAt(LocalDateTime.now());
            requestRepository.save(r);
        });
    }
}