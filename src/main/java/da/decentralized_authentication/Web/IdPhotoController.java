package da.decentralized_authentication.Web;

import da.decentralized_authentication.Model.User;
import da.decentralized_authentication.Service.AuthService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Optional;

@Controller
public class IdPhotoController {

    private final AuthService authService;

    public IdPhotoController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/register/photo")
    public String showUploadForm(@RequestParam String email, Model model) {
        Optional<User> user = authService.getUserByEmail(email); // треба овој метод да постои
        if (user.isEmpty()) return "redirect:/register";

        model.addAttribute("email", email);
        model.addAttribute("rejectionReason", user.get().getLastRejectionReason());
        return "register-photo";
    }

    @PostMapping("/register/photo")
    public String uploadPhoto(@RequestParam String email,
                              @RequestParam("photo") MultipartFile photo,
                              Model model) {
        Optional<User> user = authService.getUserByEmail(email);
        if (user.isEmpty()) return "redirect:/register";

        try {
            authService.uploadIdPhoto(user.get().getId(), photo);
            return "redirect:/register/pending";
        } catch (Exception e) {
            model.addAttribute("email", email);
            model.addAttribute("error", e.getMessage());
            return "register-photo";
        }
    }

    @GetMapping("/register/pending")
    public String pendingPage() {
        return "register-pending";
    }
}