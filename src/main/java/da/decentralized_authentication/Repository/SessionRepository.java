package da.decentralized_authentication.Repository;


import da.decentralized_authentication.Model.Session;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<Session, String> {
}