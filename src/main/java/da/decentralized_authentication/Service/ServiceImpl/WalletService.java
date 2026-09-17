package da.decentralized_authentication.Service.ServiceImpl;

import da.decentralized_authentication.Model.DidDocument;
import da.decentralized_authentication.Model.User;
import da.decentralized_authentication.Repository.DidDocumentRepository;
import da.decentralized_authentication.Repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class WalletService implements da.decentralized_authentication.Service.WalletService {

    private final DidDocumentRepository didDocumentRepository;
    private final UserRepository userRepository;

    public WalletService(DidDocumentRepository didDocumentRepository, UserRepository userRepository) {
        this.didDocumentRepository = didDocumentRepository;
        this.userRepository = userRepository;
    }

    @Override
    public String registerPublicKey(Long holderId, String username, String publicKeyJwk) {
        String did = "did:web:decentralized-auth.local:" + username;

        DidDocument doc = didDocumentRepository.findByHolderId(holderId)
                .orElse(new DidDocument());
        doc.setDid(did);
        doc.setPublicKeyJwk(publicKeyJwk);
        doc.setHolderId(holderId);
        didDocumentRepository.save(doc);

        userRepository.findById(holderId).ifPresent(u -> {
            u.setDid(did);
            userRepository.save(u);
        });

        return did;
    }
}