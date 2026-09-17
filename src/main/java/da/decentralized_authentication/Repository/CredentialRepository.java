package da.decentralized_authentication.Repository;

import da.decentralized_authentication.Model.Credential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CredentialRepository extends JpaRepository<Credential, Long> {
    List<Credential> findByHolderId(Long holderId);
}
