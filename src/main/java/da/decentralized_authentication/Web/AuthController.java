package da.decentralized_authentication.Web;

import da.decentralized_authentication.Model.Enum.VerificationResult;
import da.decentralized_authentication.Model.User;
import da.decentralized_authentication.Service.AuthService;
import da.decentralized_authentication.Service.SessionService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.Hashtable;
import java.util.Locale;
import java.util.regex.Pattern;

@Controller
public class AuthController {

    // Kept in sync with SessionServiceImpl.SESSION_HOURS so the cookie never
    // outlives or dies well before the server-side session.
    private static final int SESSION_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 4;
    private static final Pattern UNSAFE_CHARS = Pattern.compile("[<>]");
    private static final int USERNAME_MAX_LEN = 50;
    private static final int FULL_NAME_MAX_LEN = 150;
    private static final int ADDRESS_MAX_LEN = 200;
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,24}$");
    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,}$");

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
                           @RequestParam(required = false)
                           @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate dob,
                           @RequestParam String address,
                           @RequestParam String email,
                           @RequestParam String password,
                           @RequestParam String confirmPassword,
                           Model model) {

        String cleanUsername = username.trim();
        String cleanFullName = fullName.trim();
        String cleanAddress = address.trim();
        String cleanEmail = email.trim();

        String validationError = validateRegistrationInput(
                cleanUsername,
                cleanFullName,
                dob,
                cleanAddress,
                cleanEmail,
                password,
                confirmPassword
        );

        if (validationError != null) {
            return registerWithError(
                    model,
                    validationError,
                    cleanUsername,
                    cleanFullName,
                    dob,
                    cleanAddress,
                    cleanEmail
            );
        }

        boolean started;

        try {
            started = authService.startRegistration(
                    cleanUsername,
                    cleanFullName,
                    dob,
                    cleanAddress,
                    cleanEmail,
                    password
            );
        } catch (IllegalStateException e) {
            return registerWithError(
                    model,
                    "Не успеавме да го испратиме кодот на email. Обиди се повторно подоцна.",
                    cleanUsername,
                    cleanFullName,
                    dob,
                    cleanAddress,
                    cleanEmail
            );
        }

        if (!started) {
            return registerWithError(
                    model,
                    "Корисничкото име или email веќе постои",
                    cleanUsername,
                    cleanFullName,
                    dob,
                    cleanAddress,
                    cleanEmail
            );
        }

        return "redirect:/register/verify?email=" + urlEncode(cleanEmail);
    }

    private String registerWithError(Model model,
                                     String error,
                                     String username,
                                     String fullName,
                                     LocalDate dob,
                                     String address,
                                     String email) {
        model.addAttribute("error", error);
        model.addAttribute("username", username);
        model.addAttribute("fullName", fullName);
        model.addAttribute("dob", dob);
        model.addAttribute("address", address);
        model.addAttribute("email", email);
        return "register";
    }

    private String validateRegistrationInput(String username,
                                             String fullName,
                                             LocalDate dob,
                                             String address,
                                             String email,
                                             String password,
                                             String confirmPassword) {

        if (username.isEmpty()) {
            return "Корисничкото име е задолжително.";
        }

        if (username.length() > USERNAME_MAX_LEN || !isSafeText(username)) {
            return "Корисничкото име содржи недозволени знаци.";
        }

        if (fullName.isEmpty()) {
            return "Целосното име е задолжително.";
        }

        if (fullName.length() > FULL_NAME_MAX_LEN || !isSafeText(fullName)) {
            return "Целосното име содржи недозволени знаци.";
        }

        if (address.isEmpty()) {
            return "Адресата е задолжителна.";
        }

        if (address.length() > ADDRESS_MAX_LEN || !isSafeText(address)) {
            return "Адресата содржи недозволени знаци.";
        }

        if (dob == null) {
            return "Датумот на раѓање е задолжителен.";
        }

        if (email.isEmpty()) {
            return "Email адресата е задолжителна.";
        }

        if (!email.equals(email.toLowerCase(Locale.ROOT))) {
            return "Email адресата мора да биде со мали букви.";
        }

        if (!EMAIL_PATTERN.matcher(email).matches()) {
            return "Внеси важечка email адреса (на пр. korisnik@primer.com).";
        }

        String domain = email.substring(email.indexOf('@') + 1);

        if (!domainHasMailServer(domain)) {
            return "Доменот на email адресата не прима пошта.";
        }

        if (password == null
                || password.trim().isEmpty()
                || !PASSWORD_PATTERN.matcher(password).matches()) {
            return "Лозинката мора да има најмалку 8 знаци, со барем една мала буква, "
                    + "една голема буква, една бројка и еден специјален знак.";
        }

        if (!password.equals(confirmPassword)) {
            return "Лозинките не се совпаѓаат.";
        }

        return null;
    }

    private boolean isSafeText(String value) {
        if (UNSAFE_CHARS.matcher(value).find()) {
            return false;
        }

        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) {
                return false;
            }
        }

        return true;
    }

    private boolean domainHasMailServer(String domain) {
        DirContext ctx = null;

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(
                    "java.naming.factory.initial",
                    "com.sun.jndi.dns.DnsContextFactory"
            );
            env.put("com.sun.jndi.dns.timeout.initial", "2000");
            env.put("com.sun.jndi.dns.timeout.retries", "1");

            ctx = new InitialDirContext(env);

            Attributes attrs = ctx.getAttributes(
                    domain,
                    new String[]{"MX"}
            );

            Attribute mx = attrs.get("MX");

            return mx != null && mx.size() > 0;

        } catch (NamingException e) {
            return false;
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (NamingException ignored) {
                }
            }
        }
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
            case SUCCESS -> {
                User user = authService.getUserByUsername(/* треба username, не email */ email).orElse(null);
                // подобро: authService.completeRegistration да враќа username или User директно
                yield "redirect:/register/photo?email=" + email;
            }
            case EXPIRED -> withError(model, email, "Кодот истечен, регистрирај се повторно");
            case LOCKED -> withError(model, email, "Премногу обиди, регистрирај се повторно");
            default -> withError(model, email, "Погрешен код");
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
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        Model model,
                        HttpServletResponse response) {

        String cleanUsername = username.trim();

        if (!authService.checkPassword(cleanUsername, password)) {
            model.addAttribute(
                    "error",
                    "Погрешни податоци или суспендирана сметка"
            );
            return "login";
        }

        if (!authService.requiresTwoFactor(cleanUsername)) {
            String token = authService.directLogin(cleanUsername);

            if (token != null) {
                response.addCookie(
                        sessionCookie(
                                token,
                                SESSION_COOKIE_MAX_AGE_SECONDS
                        )
                );

                return "redirect:/home";
            }
        }

        try {
            authService.requestLoginCode(cleanUsername);
        } catch (IllegalStateException e) {
            model.addAttribute(
                    "error",
                    "Не успеавме да го испратиме кодот на email. Обиди се повторно подоцна."
            );
            return "login";
        }

        return "redirect:/login/verify?username=" + urlEncode(cleanUsername);
    }

    @GetMapping("/login/verify")
    public String showLoginVerify(@RequestParam String username,
                                  Model model) {
        model.addAttribute("username", username);
        return "login-verify";
    }

    @PostMapping("/login/verify")
    public String verifyLogin(@RequestParam String username,
                              @RequestParam String code,
                              Model model,
                              HttpServletResponse response) {

        String cleanUsername = username.trim();
        String cleanCode = code.trim();

        String token = authService.completeLogin(
                cleanUsername,
                cleanCode
        );

        if (token == null) {
            model.addAttribute("username", cleanUsername);
            model.addAttribute(
                    "error",
                    "Погрешен, истечен или непостоечки код"
            );
            return "login-verify";
        }

        response.addCookie(
                sessionCookie(
                        token,
                        SESSION_COOKIE_MAX_AGE_SECONDS
                )
        );

        return "redirect:/home";
    }

    @GetMapping("/home")
    public String home(
            @CookieValue(value = "session", required = false) String token) {

        if (token == null || sessionService.validate(token).isEmpty()) {
            return "redirect:/login";
        }

        return "home";
    }

    @GetMapping("/logout")
    public String logout(
            @CookieValue(value = "session", required = false) String token,
            HttpServletResponse response) {

        if (token != null) {
            sessionService.invalidate(token);
            response.addCookie(sessionCookie("", 0));
        }

        return "redirect:/login";
    }

    private Cookie sessionCookie(String value, int maxAgeSeconds) {
        Cookie cookie = new Cookie("session", value);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(maxAgeSeconds);
        cookie.setSecure(true);
        cookie.setAttribute("SameSite", "Strict");
        return cookie;
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
