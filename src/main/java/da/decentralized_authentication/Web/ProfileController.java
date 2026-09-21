package da.decentralized_authentication.Web;

import da.decentralized_authentication.Service.AuthService;
import da.decentralized_authentication.Service.CredentialService;
import da.decentralized_authentication.Service.SessionService;
import da.decentralized_authentication.Model.Credential;
import da.decentralized_authentication.Model.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@Controller
public class ProfileController {

    private final AuthService authService;
    private final CredentialService credentialService;
    private final SessionService sessionService;

    public ProfileController(AuthService authService, CredentialService credentialService,
                             SessionService sessionService) {
        this.authService = authService;
        this.credentialService = credentialService;
        this.sessionService = sessionService;
    }

    private Optional<User> currentUser(String token) {
        if (token == null) return Optional.empty();
        return sessionService.validate(token).flatMap(authService::getUserById);
    }

    @GetMapping("/profile")
    public String profile(@CookieValue(value = "session", required = false) String token, Model model) {
        Optional<User> user = currentUser(token);
        if (user.isEmpty()) return "redirect:/login";

        model.addAttribute("user", user.get());
        model.addAttribute("credentials", credentialService.getCredentialsForHolder(user.get().getId()));
        model.addAttribute("requests", credentialService.getRequestsForHolder(user.get().getId()));
        return "profile";
    }

    @PostMapping("/profile/request-credential")
    public String requestCredential(@CookieValue(value = "session", required = false) String token,
                                    @RequestParam String type,
                                    @RequestParam(required = false) String proofDocumentPath,
                                    @RequestParam(required = false) String description,
                                    RedirectAttributes redirectAttributes) {
        Optional<User> user = currentUser(token);
        if (user.isEmpty()) return "redirect:/login";

        credentialService.requestCredential(user.get().getId(), type, proofDocumentPath, description);
        redirectAttributes.addFlashAttribute("successMessage", "Барањето е испратено за преглед");
        return "redirect:/profile";
    }

    @PostMapping("/profile/update-credential")
    public String updateCredential(@CookieValue(value = "session", required = false) String token,
                                   @RequestParam Long credentialId,
                                   @RequestParam String type,
                                   RedirectAttributes redirectAttributes) {
        Optional<User> user = currentUser(token);
        if (user.isEmpty()) return "redirect:/login";

        // credential е крипт. потпишан — не се менува директно, туку revoke + ново барање
        credentialService.revokeCredential(credentialId, "Заменет со ново барање од holder-от");
        credentialService.requestCredential(user.get().getId(), type, null);

        redirectAttributes.addFlashAttribute("successMessage",
                "Стариот credential е revoke-иран, ново барање е поднесено");
        return "redirect:/profile";
    }

    @PostMapping("/profile/delete-credential")
    public String deleteCredential(@CookieValue(value = "session", required = false) String token,
                                   @RequestParam Long credentialId,
                                   RedirectAttributes redirectAttributes) {
        Optional<User> user = currentUser(token);
        if (user.isEmpty()) return "redirect:/login";

        credentialService.deleteCredential(credentialId);
        redirectAttributes.addFlashAttribute("successMessage", "Credential е избришан");
        return "redirect:/profile";
    }

    @PostMapping("/profile/update-key")
    public String updatePublicKey(@CookieValue(value = "session", required = false) String token,
                                  @RequestParam String publicKey,
                                  RedirectAttributes redirectAttributes) {
        Optional<User> user = currentUser(token);
        if (user.isEmpty()) return "redirect:/login";

        User u = user.get();
        u.setPublicKey(publicKey);
        authService.updateUser(u);
        redirectAttributes.addFlashAttribute("successMessage", "Public key е ажуриран");
        return "redirect:/profile";
    }
}