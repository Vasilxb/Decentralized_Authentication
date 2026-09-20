package da.decentralized_authentication.Web;

import da.decentralized_authentication.Model.Enum.VerificationResult;
import da.decentralized_authentication.Service.AuthService;
import da.decentralized_authentication.Service.SessionService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;

@Controller
public class AuthController {

    // Kept in sync with SessionServiceImpl.SESSION_HOURS so the cookie never
    // outlives or dies well before the server-side session.
    private static final int SESSION_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 4;

    private final AuthService authService;
    private final SessionService sessionService;

    public AuthController(AuthService authService, SessionService sessionService) {
        this.authService = authService;
        this.sessionService = sessionService;
    }

    @GetMapping("/")
    public String root() {
        return "redirect:/login";
    }

    @GetMapping("/register")
    public String showRegister() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String fullName,
                           @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate dob,
                           @RequestParam String address,
                           @RequestParam String email,
                           @RequestParam String password,
                           Model model) {
        if (!authService.startRegistration(username, fullName, dob, address, email, password)) {
            model.addAttribute("error", "Корисничкото име или email веќе постои");
            return "register";
        }
        return "redirect:/register/verify?email=" + email;
    }

    @GetMapping("/register/verify")
    public String showRegisterVerify(@RequestParam String email, Model model) {
        model.addAttribute("email", email);
        return "register-verify";
    }

    @PostMapping("/register/verify")
    public String verifyRegister(@RequestParam String email, @RequestParam String code, Model model) {
        VerificationResult result = authService.completeRegistration(email, code);
        return switch (result) {
            case SUCCESS -> "redirect:/login";
            case EXPIRED -> withError(model, email, "Кодот истече, регистрирај се повторно");
            case LOCKED -> withError(model, email, "Премногу неуспешни обиди, регистрирај се повторно");
            case USERNAME_TAKEN -> withError(model, email, "Корисничкото име веќе постои");
            case EMAIL_TAKEN -> withError(model, email, "Email адресата веќе постои");
            default -> withError(model, email, "Погрешен или непостоечки код");
        };
    }

    private String withError(Model model, String email, String message) {
        model.addAttribute("email", email);
        model.addAttribute("error", message);
        return "register-verify";
    }

    @GetMapping("/login")
    public String showLogin() {
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password,
                        Model model, HttpServletResponse response) {
        if (!authService.checkPassword(username, password)) {
            model.addAttribute("error", "Погрешни податоци или суспендирана сметка");
            return "login";
        }

        if (!authService.requiresTwoFactor(username)) {
            // DEMO BYPASS - директно сесија, без код
            String token = authService.directLogin(username);
            if (token != null) {
                Cookie cookie = new Cookie("session", token);
                cookie.setHttpOnly(true);
                cookie.setPath("/");
                response.addCookie(cookie);
                return "redirect:/home";
            }
        }

        authService.requestLoginCode(username);
        return "redirect:/login/verify?username=" + username;
    }

    @GetMapping("/login/verify")
    public String showLoginVerify(@RequestParam String username, Model model) {
        model.addAttribute("username", username);
        return "login-verify";
    }

    @PostMapping("/login/verify")
    public String verifyLogin(
            @RequestParam String username,
            @RequestParam String code,
            Model model,
            HttpServletResponse response
    ) {
        String token = authService.completeLogin(username, code);
        if (token == null) {
            model.addAttribute("username", username);
            model.addAttribute(
                    "error",
                    "Погрешен, истечен или непостоечки код"
            );
            return "login-verify";
        }
        Cookie cookie = new Cookie("session", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(SESSION_COOKIE_MAX_AGE_SECONDS);
        cookie.setSecure(true);
        cookie.setAttribute("SameSite", "Strict");
        response.addCookie(cookie);
        return "redirect:/home";
    }

    @GetMapping("/home")
    public String home(@CookieValue(value = "session", required = false) String token) {
        if (token == null || sessionService.validate(token).isEmpty()) {
            return "redirect:/login";
        }
        return "home";
    }

    @GetMapping("/logout")
    public String logout(@CookieValue(value = "session", required = false) String token,
                         HttpServletResponse response) {
        if (token != null) {
            sessionService.invalidate(token);
            Cookie cookie = new Cookie("session", "");
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        }
        return "redirect:/login";
    }
}