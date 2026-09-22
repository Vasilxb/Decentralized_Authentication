package da.decentralized_authentication.Web;

import da.decentralized_authentication.Service.AuthService;
import da.decentralized_authentication.Service.CredentialService;
import da.decentralized_authentication.Service.SessionService;
import da.decentralized_authentication.Model.User;
import da.decentralized_authentication.Model.Enum.UserRole;
import da.decentralized_authentication.Util.IdPhotoStorageService;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@Controller
public class AdminController {

    private final AuthService authService;
    private final CredentialService credentialService;
    private final SessionService sessionService;
    private final IdPhotoStorageService photoStorageService;
    public AdminController(AuthService authService, CredentialService credentialService,
                           SessionService sessionService, IdPhotoStorageService photoStorageService) {
        this.authService = authService;
        this.credentialService = credentialService;
        this.sessionService = sessionService;
        this.photoStorageService = photoStorageService;
    }

    private Optional<User> currentAdmin(String token) {
        if (token == null) return Optional.empty();
        return sessionService.validate(token).flatMap(authService::getUserById)
                .filter(u -> u.getRole() == UserRole.ADMIN);
    }

    @GetMapping("/admin/requests")
    public String pendingRequests(@CookieValue(value = "session", required = false) String token, Model model) {
        if (currentAdmin(token).isEmpty()) return "redirect:/login";
        model.addAttribute("requests", credentialService.getPendingRequests());
        return "admin-requests";
    }

    @PostMapping("/admin/requests/approve")
    public String approve(@CookieValue(value = "session", required = false) String token,
                          @RequestParam Long requestId, RedirectAttributes redirectAttributes) {
        Optional<User> admin = currentAdmin(token);
        if (admin.isEmpty()) return "redirect:/login";

        try {
            credentialService.approveRequest(requestId, admin.get().getId());
            redirectAttributes.addFlashAttribute("successMessage", "Credential е издаден и потпишан");
        } catch (IllegalStateException e) {
            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage", "Неочекувана грешка: " + e.getMessage());
        }
        return "redirect:/admin/requests";
    }

    @PostMapping("/admin/requests/deny")
    public String deny(@CookieValue(value = "session", required = false) String token,
                       @RequestParam Long requestId, RedirectAttributes redirectAttributes) {
        Optional<User> admin = currentAdmin(token);
        if (admin.isEmpty()) return "redirect:/login";

        credentialService.denyRequest(requestId, admin.get().getId());
        redirectAttributes.addFlashAttribute("successMessage", "Барањето е одбиено");
        return "redirect:/admin/requests";
    }

    @PostMapping("/admin/revoke-credential")
    public String revokeCredential(@CookieValue(value = "session", required = false) String token,
                                   @RequestParam Long credentialId,
                                   @RequestParam String reason,
                                   RedirectAttributes redirectAttributes) {
        if (currentAdmin(token).isEmpty()) return "redirect:/login";
        credentialService.revokeCredential(credentialId, reason);
        redirectAttributes.addFlashAttribute("successMessage", "Credential е revoke-иран");
        return "redirect:/admin/requests";
    }

    @GetMapping("/admin/users")
    public String viewUsers(@CookieValue(value = "session", required = false) String token, Model model) {
        if (currentAdmin(token).isEmpty()) return "redirect:/login";
        model.addAttribute("users", authService.getAllUsers());
        return "admin-users";
    }

    @PostMapping("/admin/users/suspend")
    public String suspendUser(@CookieValue(value = "session", required = false) String token,
                              @RequestParam String username, RedirectAttributes redirectAttributes) {
        if (currentAdmin(token).isEmpty()) return "redirect:/login";
        authService.revokeUser(username);
        redirectAttributes.addFlashAttribute("successMessage", "Сметката на " + username + " е суспендирана");
        return "redirect:/admin/users";
    }

    @PostMapping("/admin/users/enable")
    public String enableUser(@CookieValue(value = "session", required = false) String token,
                             @RequestParam String username, RedirectAttributes redirectAttributes) {
        if (currentAdmin(token).isEmpty()) return "redirect:/login";
        authService.enableUser(username);
        redirectAttributes.addFlashAttribute("successMessage", "Сметката на " + username + " е активирана");
        return "redirect:/admin/users";
    }

    @GetMapping("/admin/activations")
    public String pendingActivations(@CookieValue(value = "session", required = false) String token, Model model) {
        if (currentAdmin(token).isEmpty()) return "redirect:/login";
        model.addAttribute("users", authService.getPendingReviewUsers());
        return "admin-activations";
    }

    @GetMapping("/admin/activations/photo/{userId}")
    @ResponseBody
    public ResponseEntity<byte[]> viewPhoto(@CookieValue(value = "session", required = false) String token,
                                            @PathVariable Long userId) throws Exception {
        if (currentAdmin(token).isEmpty()) return ResponseEntity.status(401).build();

        User user = authService.getUserById(userId).orElseThrow();
        byte[] imageBytes = photoStorageService.read(user.getIdPhotoPath());
        return ResponseEntity.ok().header("Content-Type", "image/jpeg").body(imageBytes);
    }

    @PostMapping("/admin/activations/approve")
    public String approveActivation(@CookieValue(value = "session", required = false) String token,
                                    @RequestParam Long userId, RedirectAttributes redirectAttributes) {
        if (currentAdmin(token).isEmpty()) return "redirect:/login";
        authService.approveIdPhoto(userId);
        redirectAttributes.addFlashAttribute("successMessage", "Сметката е активирана");
        return "redirect:/admin/activations";
    }

    @PostMapping("/admin/activations/reject")
    public String rejectActivation(@CookieValue(value = "session", required = false) String token,
                                   @RequestParam Long userId, @RequestParam String reason,
                                   RedirectAttributes redirectAttributes) {
        if (currentAdmin(token).isEmpty()) return "redirect:/login";
        authService.rejectIdPhoto(userId, reason);
        redirectAttributes.addFlashAttribute("successMessage", "Барањето е одбиено");
        return "redirect:/admin/activations";
    }
}