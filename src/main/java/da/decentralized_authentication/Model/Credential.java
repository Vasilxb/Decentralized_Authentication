package da.decentralized_authentication.Model;

import da.decentralized_authentication.Model.Enum.CredentialStatus;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "credentials")
@Getter
@Setter
@NoArgsConstructor
public class Credential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long holderId;

    private String type;

    @Column(columnDefinition = "TEXT")
    private String issuerSignature;

    @Column(columnDefinition = "TEXT")
    private String holderPublicKeySnapshot;

    @Enumerated(EnumType.STRING)
    private CredentialStatus status = CredentialStatus.ACTIVE;

    private LocalDateTime issuedAt = LocalDateTime.now();
    private LocalDateTime revokedAt;
    private String revokeReason;

    public Credential(Long holderId, String type, String issuerSignature, String holderPublicKeySnapshot) {
        this.holderId = holderId;
        this.type = type;
        this.issuerSignature = issuerSignature;
        this.holderPublicKeySnapshot = holderPublicKeySnapshot;
    }
}