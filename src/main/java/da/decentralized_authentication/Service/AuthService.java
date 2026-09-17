package da.decentralized_authentication.Service;

import da.decentralized_authentication.Model.User;
import da.decentralized_authentication.Model.Enum.VerificationResult;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

public interface AuthService {
    boolean startRegistration(String username, String fullName, LocalDate dob,
                              String address, String email, String password);
    VerificationResult completeRegistration(String email, String code);
    boolean checkPassword(String username, String password);
    void requestLoginCode(String username);
    String completeLogin(String username, String code);
    void revokeUser(String username);
    Optional<User> getUserByUsername(String username);
    Optional<User> getUserById(Long id);
    List<User> getAllUsers();
    void updateUser(User user);
    void enableUser(String username);
}
