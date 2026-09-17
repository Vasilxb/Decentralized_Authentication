package da.decentralized_authentication.Util;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.security.*;
import java.util.Base64;

@Component
public class IssuerKeyService {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    public void generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
        System.out.println("[Issuer] Нов RSA клуч пар генериран при стартување");
    }

    public String sign(String data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public boolean verify(String data, String signatureBase64) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data.getBytes("UTF-8"));
        return signature.verify(Base64.getDecoder().decode(signatureBase64));
    }

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}