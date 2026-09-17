package da.decentralized_authentication.Service.ServiceImpl;

import da.decentralized_authentication.Model.DidDocument;
import da.decentralized_authentication.Repository.DidDocumentRepository;
import da.decentralized_authentication.Repository.UserRepository;
import da.decentralized_authentication.Service.CredentialService;
import da.decentralized_authentication.Util.JwkValidator;
import org.springframework.stereotype.Service;

@Service
public class WalletServiceImpl implements da.decentralized_authentication.Service.WalletService {

    private final DidDocumentRepository didDocumentRepository;
    private final UserRepository userRepository;
    private final CredentialService credentialService;
    private final JwkValidator jwkValidator;

    public WalletServiceImpl(DidDocumentRepository didDocumentRepository, UserRepository userRepository, CredentialService credentialService, JwkValidator jwkValidator) {
        this.didDocumentRepository = didDocumentRepository;
        this.userRepository = userRepository;
        this.credentialService = credentialService;
        this.jwkValidator = jwkValidator;
    }

    @Override
    public String registerPublicKey(Long holderId, String username, String publicKeyJwk) {
        jwkValidator.validate(publicKeyJwk);

        String did = "did:web:decentralized-auth.local:" + username;

        boolean isRotation = didDocumentRepository.findByHolderId(holderId).isPresent();

        DidDocument doc = didDocumentRepository.findByHolderId(holderId).orElse(new DidDocument());
        doc.setDid(did);
        doc.setPublicKeyJwk(publicKeyJwk);
        doc.setHolderId(holderId);
        didDocumentRepository.save(doc);

        userRepository.findById(holderId).ifPresent(u -> {
            u.setDid(did);
            userRepository.save(u);
        });

        if (isRotation) {
            credentialService.revokeAllForHolder(holderId, "Wallet клучот е ротиран - стариот credential повеќе не може да се докаже");
        }

        return did;
    }
}