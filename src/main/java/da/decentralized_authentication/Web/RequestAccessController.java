package da.decentralized_authentication.Web;

import da.decentralized_authentication.Service.AuthService;
import da.decentralized_authentication.Service.CredentialService;
import da.decentralized_authentication.Service.SessionService;
import da.decentralized_authentication.Service.VerifierService;
import da.decentralized_authentication.Model.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@Controller
public class RequestAccessController {

    private final AuthService authService;
    private final VerifierService verifierService;
    private final CredentialService credentialService;
    private final SessionService sessionService;

    public RequestAccessController(AuthService authService, VerifierService verifierService,
                                   CredentialService credentialService, SessionService sessionService) {
        this.authService = authService;
        this.verifierService = verifierService;
        this.credentialService = credentialService;
        this.sessionService = sessionService;
    }

    private Optional<User> currentUser(String token) {
        if (token == null) return Optional.empty();
        return sessionService.validate(token).flatMap(authService::getUserById);
    }

    @GetMapping("/requestAccess")
    public String showRequests(@CookieValue(value = "session", required = false) String token, Model model) {
        Optional<User> user = currentUser(token);
        if (user.isEmpty()) return "redirect:/login";

        model.addAttribute("requests", verifierService.getRequestsForHolder(user.get().getId()));
        model.addAttribute("credentials", credentialService.getCredentialsForHolder(user.get().getId()));
        return "request-access";
    }

    @PostMapping("/requestAccess/approve")
    public String approve(@CookieValue(value = "session", required = false) String token,
                          @RequestParam Long requestId,
                          @RequestParam Long credentialId,
                          RedirectAttributes redirectAttributes) {
        if (currentUser(token).isEmpty()) return "redirect:/login";
        verifierService.approve(requestId, credentialId);
        redirectAttributes.addFlashAttribute("successMessage", "Барањето е одобрено");
        return "redirect:/requestAccess";
    }

    @PostMapping("/requestAccess/deny")
    public String deny(@CookieValue(value = "session", required = false) String token,
                       @RequestParam Long requestId, RedirectAttributes redirectAttributes) {
        if (currentUser(token).isEmpty()) return "redirect:/login";
        verifierService.deny(requestId);
        redirectAttributes.addFlashAttribute("successMessage", "Барањето е одбиено");
        return "redirect:/requestAccess";
    }
}