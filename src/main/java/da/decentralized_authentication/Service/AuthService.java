package da.decentralized_authentication.Service;

import da.decentralized_authentication.Model.User;
import da.decentralized_authentication.Model.Enum.VerificationResult;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

public interface AuthService {
    boolean startRegistration(String username, String fullName, LocalDate dob,
                              String address, String email, String password);
    VerificationResult completeRegistration(String email, String code);
    boolean checkPassword(String username, String password);
    boolean requiresTwoFactor(String username); // НОВО
    void requestLoginCode(String username);
    String directLogin(String username); // НОВО - за bypass случаи
    String completeLogin(String username, String code);
    void revokeUser(String username);
    Optional<User> getUserByUsername(String username);
    Optional<User> getUserById(Long id);
    Optional<User> getUserByEmail(String email);
    List<User> getAllUsers();
    void updateUser(User user);

    void enableUser(String username);
    void uploadIdPhoto(Long userId, MultipartFile file) throws Exception;
    void approveIdPhoto(Long userId);
    void rejectIdPhoto(Long userId, String reason);
    List<User> getPendingReviewUsers();
}
