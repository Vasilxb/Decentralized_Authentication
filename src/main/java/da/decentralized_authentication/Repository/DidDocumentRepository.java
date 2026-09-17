package da.decentralized_authentication.Repository;


import da.decentralized_authentication.Model.DidDocument;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DidDocumentRepository extends JpaRepository<DidDocument, Long> {
    Optional<DidDocument> findByDid(String did);
    Optional<DidDocument> findByHolderId(Long holderId);
}