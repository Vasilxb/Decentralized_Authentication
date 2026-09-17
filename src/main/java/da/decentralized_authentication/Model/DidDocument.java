package da.decentralized_authentication.Model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "did_documents")
@Getter
@Setter
@NoArgsConstructor
public class DidDocument {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String did; // на пр. "did:web:decentralized-auth.local:lalala"

    @Column(columnDefinition = "TEXT", nullable = false)
    private String publicKeyJwk; // JSON string од exportKey("jwk", ...)

    // ВНИМАНИЕ: ова поле е само за внатрешна употреба на серверот,
    // никогаш не се вклучува во јавниот DID document JSON одговор
    @Column(nullable = false)
    private Long holderId;

    private LocalDateTime createdAt = LocalDateTime.now();

    public DidDocument(String did, String publicKeyJwk, Long holderId) {
        this.did = did;
        this.publicKeyJwk = publicKeyJwk;
        this.holderId = holderId;
    }
}