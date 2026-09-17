package da.decentralized_authentication.Model;

import da.decentralized_authentication.Model.Enum.VerificationType;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "verification_codes")
@Getter
@Setter
@NoArgsConstructor
public class VerificationCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String identifier;

    @Column(nullable = false)
    private String codeHash;

    @Column(nullable = false)
    private String salt;

    @Enumerated(EnumType.STRING)
    private VerificationType type;

    private LocalDateTime expiresAt;
    private boolean used = false;
    private int attemptCount = 0;

    // pending регистрациски податоци (само за REGISTER тип)
    private String pendingUsername;
    private String pendingFullName;
    private LocalDate pendingDateOfBirth;
    private String pendingAddress;
    private String pendingPasswordHash;
    private String pendingPasswordSalt;

    public VerificationCode(String identifier, String codeHash, String salt,
                            VerificationType type, LocalDateTime expiresAt) {
        this.identifier = identifier;
        this.codeHash = codeHash;
        this.salt = salt;
        this.type = type;
        this.expiresAt = expiresAt;
    }
}