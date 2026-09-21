package da.decentralized_authentication.Model;


import da.decentralized_authentication.Model.Enum.VerifierRequestStatus;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "verifier_requests")
@Getter
@Setter
@NoArgsConstructor
public class VerifierRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long holderId;

    private String verifierName;
    private String requestedCredentialType;
    private Long credentialId; // НОВО - се пополнува само при approve

    @Enumerated(EnumType.STRING)
    private VerifierRequestStatus status = VerifierRequestStatus.PENDING;

    private LocalDateTime requestedAt = LocalDateTime.now();
    private LocalDateTime respondedAt;

    public VerifierRequest(Long holderId, String verifierName, String requestedCredentialType) {
        this.holderId = holderId;
        this.verifierName = verifierName;
        this.requestedCredentialType = requestedCredentialType;
    }
}