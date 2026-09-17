package da.decentralized_authentication.Web;

import da.decentralized_authentication.Model.DidDocument;
import da.decentralized_authentication.Repository.DidDocumentRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class DidResolverController {

    private final DidDocumentRepository didDocumentRepository;

    public DidResolverController(DidDocumentRepository didDocumentRepository) {
        this.didDocumentRepository = didDocumentRepository;
    }

    @GetMapping(value = "/did/{username}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> resolveDid(@PathVariable String username) {
        String did = "did:web:decentralized-auth.local:" + username;

        return didDocumentRepository.findByDid(did)
                .map(doc -> ResponseEntity.ok(buildDidDocumentJson(doc)))
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("{\"error\": \"DID not found\"}"));
    }

    private String buildDidDocumentJson(DidDocument doc) {
        return """
                {
                  "@context": "https://www.w3.org/ns/did/v1",
                  "id": "%s",
                  "verificationMethod": [{
                    "id": "%s#key-1",
                    "type": "JsonWebKey2020",
                    "controller": "%s",
                    "publicKeyJwk": %s
                  }],
                  "authentication": ["%s#key-1"]
                }
                """.formatted(doc.getDid(), doc.getDid(), doc.getDid(), doc.getPublicKeyJwk(), doc.getDid());
    }
}