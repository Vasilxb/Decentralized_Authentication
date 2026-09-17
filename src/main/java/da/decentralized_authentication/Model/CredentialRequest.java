package da.decentralized_authentication.Model;

import da.decentralized_authentication.Model.Enum.CredentialRequestStatus;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "credential_requests")
@Getter
@Setter
@NoArgsConstructor
public class CredentialRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long holderId;

    private String requestedType;
    private String proofDocumentPath;

    @Enumerated(EnumType.STRING)
    private CredentialRequestStatus status = CredentialRequestStatus.PENDING;

    private LocalDateTime requestedAt = LocalDateTime.now();
    private LocalDateTime reviewedAt;
    private Long reviewedByAdminId;

    public CredentialRequest(Long holderId, String requestedType, String proofDocumentPath) {
        this.holderId = holderId;
        this.requestedType = requestedType;
        this.proofDocumentPath = proofDocumentPath;
    }
}