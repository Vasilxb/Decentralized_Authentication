package da.decentralized_authentication.Web;

import da.decentralized_authentication.Service.AuthService;
import da.decentralized_authentication.Service.SessionService;
import da.decentralized_authentication.Service.WalletService;
import da.decentralized_authentication.Model.User;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
public class WalletController {

    private final AuthService authService;
    private final SessionService sessionService;
    private final WalletService walletService;

    public WalletController(AuthService authService, SessionService sessionService, WalletService walletService) {
        this.authService = authService;
        this.sessionService = sessionService;
        this.walletService = walletService;
    }

    private Optional<User> currentUser(String token) {
        if (token == null) return Optional.empty();
        return sessionService.validate(token).flatMap(authService::getUserById);
    }

    @GetMapping("/wallet")
    public String wallet(@CookieValue(value = "session", required = false) String token, Model model) {
        Optional<User> user = currentUser(token);
        if (user.isEmpty()) return "redirect:/login";

        model.addAttribute("username", user.get().getUsername());
        model.addAttribute("existingDid", user.get().getDid());
        return "wallet";
    }

    @PostMapping("/wallet/register-key")
    public ResponseEntity<String> registerKey(@CookieValue(value = "session", required = false) String token,
                                              @RequestBody WalletKeyRequest request) {
        Optional<User> user = currentUser(token);
        if (user.isEmpty()) {
            return ResponseEntity.status(401).body("Не си најавен");
        }

        String did = walletService.registerPublicKey(
                user.get().getId(), user.get().getUsername(), request.publicKeyJwk());
        return ResponseEntity.ok(did);
    }

    public record WalletKeyRequest(String publicKeyJwk) {}
}