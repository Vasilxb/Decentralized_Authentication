package da.decentralized_authentication.Service.ServiceImpl;

import da.decentralized_authentication.Model.Enum.CredentialRequestStatus;
import da.decentralized_authentication.Model.Enum.CredentialStatus;
import da.decentralized_authentication.Model.*;
import da.decentralized_authentication.Repository.CredentialRepository;
import da.decentralized_authentication.Repository.CredentialRequestRepository;
import da.decentralized_authentication.Repository.DidDocumentRepository;
import da.decentralized_authentication.Util.IssuerKeyService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class CredentialServiceImpl implements da.decentralized_authentication.Service.CredentialService {

    private final CredentialRequestRepository requestRepository;
    private final CredentialRepository credentialRepository;
    private final DidDocumentRepository didDocumentRepository;
    private final IssuerKeyService issuerKeyService;


    public CredentialServiceImpl(CredentialRequestRepository requestRepository,
                                 CredentialRepository credentialRepository,
                                 DidDocumentRepository didDocumentRepository,
                                 IssuerKeyService issuerKeyService) {
        this.requestRepository = requestRepository;
        this.credentialRepository = credentialRepository;
        this.didDocumentRepository = didDocumentRepository;
        this.issuerKeyService = issuerKeyService;
    }

    @Override
    public CredentialRequest requestCredential(Long holderId, String type, String proofDocumentPath) {
        return requestRepository.save(new CredentialRequest(holderId, type, proofDocumentPath));
    }

    @Override
    public List<CredentialRequest> getPendingRequests() {
        return requestRepository.findByStatus(CredentialRequestStatus.PENDING);
    }

    @Override
    public List<CredentialRequest> getRequestsForHolder(Long holderId) {
        return requestRepository.findByHolderId(holderId);
    }

    @Override
    public void approveRequest(Long requestId, Long adminId) throws Exception {
        CredentialRequest req = requestRepository.findById(requestId)
                .orElseThrow(() -> new IllegalArgumentException("Барањето не постои"));

        // НОВО: барам DidDocument наместо да читам User.getPublicKey()
        DidDocument didDoc = didDocumentRepository.findByHolderId(req.getHolderId())
                .orElseThrow(() -> new IllegalStateException(
                        "Holder нема регистриран DID/wallet клуч. Credential не може да се издаде."));

        req.setStatus(CredentialRequestStatus.APPROVED);
        req.setReviewedAt(LocalDateTime.now());
        req.setReviewedByAdminId(adminId);
        requestRepository.save(req);

        String publicKeySnapshot = didDoc.getPublicKeyJwk();
        String dataToSign = req.getHolderId() + "|" + req.getRequestedType() + "|" + publicKeySnapshot;
        String signature = issuerKeyService.sign(dataToSign);

        credentialRepository.save(new Credential(req.getHolderId(), req.getRequestedType(),
                signature, publicKeySnapshot));
    }

    @Override
    public void denyRequest(Long requestId, Long adminId) {
        requestRepository.findById(requestId).ifPresent(req -> {
            req.setStatus(CredentialRequestStatus.DENIED);
            req.setReviewedAt(LocalDateTime.now());
            req.setReviewedByAdminId(adminId);
            requestRepository.save(req);
        });
    }

    @Override
    public List<Credential> getCredentialsForHolder(Long holderId) {
        return credentialRepository.findByHolderId(holderId);
    }

    @Override
    public void revokeCredential(Long credentialId, String reason) {
        credentialRepository.findById(credentialId).ifPresent(c -> {
            c.setStatus(CredentialStatus.REVOKED);
            c.setRevokedAt(LocalDateTime.now());
            c.setRevokeReason(reason);
            credentialRepository.save(c);
        });
    }

    @Override
    public void revokeAllForHolder(Long holderId, String reason) {
        for (Credential c : credentialRepository.findByHolderId(holderId)) {
            if (c.getStatus() == CredentialStatus.ACTIVE) {
                c.setStatus(CredentialStatus.REVOKED);
                c.setRevokedAt(LocalDateTime.now());
                c.setRevokeReason(reason);
                credentialRepository.save(c);
            }
        }
    }

    @Override
    public void deleteCredential(Long credentialId) {
        credentialRepository.findById(credentialId).ifPresent(credentialRepository::delete);
    }

    @Override
    public boolean verifyCredential(Long credentialId) throws Exception {
        Credential c = credentialRepository.findById(credentialId)
                .orElseThrow(() -> new IllegalArgumentException("Credential не постои"));
        if (c.getStatus() == CredentialStatus.REVOKED) return false;

        String dataToVerify = c.getHolderId() + "|" + c.getType() + "|" + c.getHolderPublicKeySnapshot();
        return issuerKeyService.verify(dataToVerify, c.getIssuerSignature());
    }
}