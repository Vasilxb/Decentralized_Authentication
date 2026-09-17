package da.decentralized_authentication.Util;

import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@Component
public class JwkValidator {

    private final ObjectMapper objectMapper =  new ObjectMapper();

    public void validate(String publicKeyJwk) {
        if (publicKeyJwk == null || publicKeyJwk.isBlank())
        {
            throw new IllegalArgumentException("Public key не смее да биде празен");
        }

        JsonNode json;
        try {
            json = objectMapper.readTree(publicKeyJwk);
        } catch (Exception e) {
            throw new IllegalArgumentException("Public key не е валиден JSON");
        }

        String kty = json.path("kty").asText(null);
        if (!"EC".equals(kty)) {
            throw new IllegalArgumentException("kty мора да биде 'EC', добиено: " + kty);
        }

        String crv = json.path("crv").asText(null);
        if (!"P-256".equals(crv)) {
            throw new IllegalArgumentException("crv мора да биде 'P-256', добиено: " + crv);
        }

        String x = json.path("x").asText(null);
        if (x == null || x.isBlank()) {
            throw new IllegalArgumentException("Недостасува 'x' координата");
        }

        String y = json.path("y").asText(null);
        if (y == null || y.isBlank()) {
            throw new IllegalArgumentException("Недостасува 'y' координата");
        }
    }
}