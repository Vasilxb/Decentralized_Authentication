package da.decentralized_authentication.Model;

import da.decentralized_authentication.Model.Enum.AccountStatus;
import da.decentralized_authentication.Model.Enum.UserRole;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;


@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String fullName;

    private LocalDate dateOfBirth;

    @Column(nullable = false)
    private String address;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private String salt;

    @Enumerated(EnumType.STRING)
    private UserRole role = UserRole.USER;

    private boolean enabled = true;

    @Column(columnDefinition = "TEXT")
    private String publicKey; // holder-ов public key, испратен клиентски

    private String did;

    @Enumerated(EnumType.STRING)
    @Column(columnDefinition = "varchar(20) default 'ACTIVE'")
    private AccountStatus accountStatus = AccountStatus.PENDING_PHOTO;

    private String idPhotoPath;
    @Column(nullable = false)
    private int idPhotoRejectionCount = 0;
    private String lastRejectionReason;

    public User(String username, String fullName, LocalDate dateOfBirth, String address,
                String email, String passwordHash, String salt) {
        this.username = username;
        this.fullName = fullName;
        this.dateOfBirth = dateOfBirth;
        this.address = address;
        this.email = email;
        this.passwordHash = passwordHash;
        this.salt = salt;
    }
}