package da.decentralized_authentication.Web;

import da.decentralized_authentication.Model.Credential;
import da.decentralized_authentication.Model.User;
import da.decentralized_authentication.Model.VerifierRequest;
import da.decentralized_authentication.Model.Enum.VerifierRequestStatus;
import da.decentralized_authentication.Service.AuthService;
import da.decentralized_authentication.Service.CredentialService;
import da.decentralized_authentication.Service.VerifierService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
public class VerifierController {

    private final AuthService authService;
    private final VerifierService verifierService;
    private final CredentialService credentialService;

    public VerifierController(AuthService authService,
                              VerifierService verifierService,
                              CredentialService credentialService) {
        this.authService = authService;
        this.verifierService = verifierService;
        this.credentialService = credentialService;
    }

    // Отворање на verifier страницата
    @GetMapping("/verifier")
    public String verifierPage(Model model) {
        return "verifier";
    }

    // Verifier поднесува request
    @PostMapping("/verify/request")
    public String submitRequest(
            @RequestParam String holderUsername,
            @RequestParam String verifierName,
            @RequestParam String credentialType,
            Model model) {

        Optional<User> holder = authService.getUserByUsername(holderUsername);

        if (holder.isEmpty()) {
            model.addAttribute("error", "Holder не постои.");
            return "verifier";
        }

        VerifierRequest req = verifierService.submitRequest(
                holder.get().getId(),
                verifierName,
                credentialType
        );

        model.addAttribute("requestId", req.getId());
        model.addAttribute("success",
                "Барањето е успешно испратено. Request ID: " + req.getId());

        return "verifier";
    }

    // Проверка на статус
    @GetMapping("/verify/status/{requestId}")
    public String checkStatus(
            @PathVariable Long requestId,
            Model model) {

        Optional<VerifierRequest> reqOpt =
                verifierService.getRequestById(requestId);

        if (reqOpt.isEmpty()) {
            model.addAttribute("error", "Барањето не постои.");

            return "verifier";
        }

        VerifierRequest req = reqOpt.get();

        model.addAttribute("request", req);

        // Ако сè уште не е approve
        if (req.getStatus() != VerifierRequestStatus.APPROVED) {

            model.addAttribute("status", req.getStatus().name());
            model.addAttribute("valid", false);

            return "verifier";
        }

        // Request е APPROVED, па го земаме credential-от
        Optional<Credential> credOpt =
                credentialService.getCredentialById(req.getCredentialId());

        if (credOpt.isEmpty()) {
            model.addAttribute("status", "APPROVED");
            model.addAttribute("valid", false);
            model.addAttribute("error", "Credential не постои.");

            return "verifier";
        }

        Credential credential = credOpt.get();

        boolean valid;

        try {
            valid = credentialService.verifyCredential(credential.getId());
        } catch (Exception e) {
            valid = false;
        }

        model.addAttribute("status", "APPROVED");
        model.addAttribute("credentialType", credential.getType());
        model.addAttribute("description", credential.getDescription());
        model.addAttribute("valid", valid);

        return "verifier";
    }
}